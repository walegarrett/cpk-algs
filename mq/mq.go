package mq

import (
	"bytes"
	"context"
	"cpk-algs/base"
	"cpk-algs/base/edwards25519"
	"cpk-algs/logger"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	KeepAlivePeriod = time.Second
	MaxBufferSize   = 2 * 1024 * 1024
	ReadDeadLine    = 5 * time.Second
	WriteDeadLine   = 5 * time.Second
	ConnChanSize    = 16
	SendDeadLine    = time.Second
	TickTime        = time.Second
)

type MessageQueue struct {
	cfg          *Config
	router       *gin.Engine
	server       *http.Server
	listener     *net.TCPListener
	connPoolLock sync.RWMutex
	connPool     map[string]map[string]*MessageConn
}

type MessageConn struct {
	mq                  *MessageQueue
	conn                *net.TCPConn
	remoteAddr, channel string
	buf                 chan []byte
	ctx                 context.Context
	cancel              context.CancelFunc
}

type publishJSONForm struct {
	Password string `json:"password"`
	Channel  string `json:"channel"`
	Data     string `json:"data"` // hex-encoding
}

func NewMessageQueue(cfg *Config) *MessageQueue {
	mq := &MessageQueue{
		cfg:      cfg,
		connPool: make(map[string]map[string]*MessageConn),
	}
	return mq
}

func ErrorResponse(c *gin.Context, reason string, err error) {
	logger.Logger.Warn("Request failed", "reason", reason, "err", err)
	if len(reason) == 0 {
		if err == nil {
			reason = "unknown error"
		} else {
			reason = err.Error()
		}
	} else {
		if err != nil {
			reason += ": " + err.Error()
		}
	}
	c.JSON(200, gin.H{
		"ok":      false,
		"message": reason,
	})
}

func SuccessResponse(c *gin.Context) {
	c.JSON(200, gin.H{
		"ok":      true,
		"message": "success",
	})
}

func (mq *MessageQueue) Run() (err error) {
	router := gin.New()
	router.Use(gin.LoggerWithWriter(logger.LogWriter), gin.Recovery())
	router.POST("/publish", func(c *gin.Context) {
		var form publishJSONForm
		err := c.ShouldBindJSON(&form)
		if err != nil {
			ErrorResponse(c, "parse failed", err)
			return
		}
		err = base.PasswordVerify(mq.cfg.PasswordHash, form.Password)
		if err != nil {
			ErrorResponse(c, "password error", err)
			return
		}
		data, err := hex.DecodeString(form.Data)
		if err != nil {
			ErrorResponse(c, "bad hex", err)
			return
		}
		mq.Send(form.Channel, data)
		SuccessResponse(c)
	})
	mq.server = &http.Server{Addr: fmt.Sprintf(":%d", mq.cfg.NodePort), Handler: router.Handler()}
	go func() {
		if err := mq.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Logger.Crit("Listen node failed", "err", err)
		}
	}()
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", mq.cfg.ClientPort))
	if err != nil {
		logger.Logger.Error("Resolve client addr failed", "err", err)
		return err
	}
	mq.listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		logger.Logger.Error("Listen client failed", "err", err)
		return err
	}
	go func() {
		for {
			conn, err := mq.listener.AcceptTCP()
			if err != nil {
				if opError, ok := err.(*net.OpError); (ok && opError == net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				logger.Logger.Error("Accept failed", "err", err)
				continue
			}
			go mq.handshake(conn)
		}
	}()

	return nil
}

func readWithLength(reader *net.TCPConn) (buf []byte, err error) {
	err = reader.SetReadDeadline(time.Now().Add(ReadDeadLine))
	if err != nil {
		return
	}
	var length uint64
	err = binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		return
	}
	if length > MaxBufferSize {
		logger.Logger.Warn("Receive too big buffer", "length", length, "limit", MaxBufferSize)
		return nil, errors.New("size is to big")
	}
	err = reader.SetReadDeadline(time.Now().Add(ReadDeadLine))
	if err != nil {
		return
	}
	buf = make([]byte, length)
	_, err = io.ReadFull(reader, buf)
	return
}

func writeWithLength(writer *net.TCPConn, buf []byte) (err error) {
	if buf == nil {
		err = writer.SetWriteDeadline(time.Now().Add(WriteDeadLine))
		if err != nil {
			return
		}
		empty := [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		_, err = writer.Write(empty[:])
		return
	}
	if len(buf) > MaxBufferSize {
		logger.Logger.Warn("Try to write too big buffer", "length", len(buf), "limit", MaxBufferSize)
		return errors.New("size is to big")
	}
	err = writer.SetWriteDeadline(time.Now().Add(WriteDeadLine))
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, uint64(len(buf)))
	if err != nil {
		return
	}
	_, err = writer.Write(buf)
	return
}

func (mq *MessageQueue) handshake(conn *net.TCPConn) {
	err := conn.SetKeepAlive(true)
	if err != nil {
		logger.Logger.Warn("Set keep alive failed", "err", err)
	}
	err = conn.SetKeepAlivePeriod(KeepAlivePeriod)
	if err != nil {
		logger.Logger.Warn("Set keep alive period failed", "err", err)
	}
	var randomBytes [64]byte
	_, err = rand.Read(randomBytes[:])
	if err != nil {
		panic(err)
	}
	randomScalar := (&edwards25519.Scalar{}).SetUniformBytes(randomBytes[:])
	var randomPriv base.PrivateKey
	randomPriv.Scalar = randomScalar
	randomPoint := (&edwards25519.Point{}).ScalarBaseMult(randomScalar)
	randomPointBuf := randomPoint.Bytes()
	sign := mq.cfg.SKey.Sign(randomPointBuf)
	var buf bytes.Buffer
	buf.Write(randomPointBuf)
	buf.Write(sign.Bytes())
	handshakeBuf := buf.Bytes()
	err = conn.SetWriteDeadline(time.Now().Add(WriteDeadLine))
	if err != nil {
		logger.Logger.Warn("Set write handshake deadline failed", "err", err)
		_ = conn.Close()
		return
	}
	_, err = conn.Write(handshakeBuf)
	if err != nil {
		logger.Logger.Warn("Write handshake failed", "err", err)
		_ = conn.Close()
		return
	}
	recvBuf, err := readWithLength(conn)
	if err != nil {
		logger.Logger.Warn("Read handshake failed", "err", err)
		_ = conn.Close()
		return
	}
	if len(recvBuf) <= 32 {
		logger.Logger.Warn("Read handshake packet too small")
		_ = conn.Close()
		return
	}
	key, err := randomPriv.KxReceive(recvBuf[:32])
	if err != nil {
		logger.Logger.Warn("Key exchange failed for bad point", "err", err)
		_ = conn.Close()
		return
	}
	var c base.Cipher
	copy(c[:], key[:32])
	decipher, err := c.Decipher(recvBuf[32:])
	if err != nil {
		logger.Logger.Warn("Key exchange failed for bad message", "err", err)
		_ = conn.Close()
		return
	}
	channel := string(decipher)
	mq.connPoolLock.Lock()
	defer mq.connPoolLock.Unlock()
	if cur, ok := mq.connPool[channel]; !ok || cur == nil {
		mq.connPool[channel] = make(map[string]*MessageConn)
	}
	curChannel := mq.connPool[channel]
	remoteAddr := conn.RemoteAddr().String()
	if remote, ok := curChannel[remoteAddr]; ok && remote != nil {
		err = remote.Shutdown()
		logger.Logger.Warn("Shutdown older tcp connection failed", "err", err, "remote_addr", remoteAddr, "channel", channel)
	}
	mc := &MessageConn{
		mq:         mq,
		conn:       conn,
		remoteAddr: remoteAddr,
		channel:    channel,
		buf:        make(chan []byte, ConnChanSize),
	}
	mc.ctx, mc.cancel = context.WithCancel(context.Background())
	curChannel[remoteAddr] = mc
	logger.Logger.Info("Start listening", "remote_addr", remoteAddr, "channel", channel)
	go mc.Loop()
}

func (mc *MessageConn) forceClose() {
	{
		mc.mq.connPoolLock.Lock()
		defer mc.mq.connPoolLock.Unlock()
		c, ok := mc.mq.connPool[mc.channel]
		if ok && c != nil {
			if c[mc.remoteAddr] == mc {
				delete(c, mc.remoteAddr)
			} else {
				logger.Logger.Info("The listener is not closing", "remote_addr", mc.remoteAddr, "channel", mc.channel)
			}
		}
	}
	_ = mc.Shutdown()
}

func (mc *MessageConn) sendImm(data []byte) bool {
	err := writeWithLength(mc.conn, data)
	if err != nil {
		logger.Logger.Info("Write data failed", "remote_addr", mc.remoteAddr, "channel", mc.channel)
		mc.forceClose()
		return false
	}
	err = mc.conn.SetReadDeadline(time.Now().Add(ReadDeadLine))
	if err != nil {
		logger.Logger.Info("Set read deadline failed", "remote_addr", mc.remoteAddr, "channel", mc.channel)
		mc.forceClose()
		return false
	}
	var recv [1]byte
	_, err = io.ReadFull(mc.conn, recv[:])
	if err != nil {
		logger.Logger.Info("Read data failed", "remote_addr", mc.remoteAddr, "channel", mc.channel)
		mc.forceClose()
		return false
	}
	if recv[0] != byte('!') {
		logger.Logger.Info("Bad recv", "remote_addr", mc.remoteAddr, "channel", mc.channel)
		mc.forceClose()
		return false
	}
	return true
}

func (mc *MessageConn) Loop() {
	for {
		ctx, cancel := context.WithDeadline(mc.ctx, time.Now().Add(TickTime))
		select {
		case <-ctx.Done():
			cancel()
			if ctx.Err() == context.DeadlineExceeded {
				logger.Logger.Debug("Send tick", "remote_addr", mc.remoteAddr, "channel", mc.channel)
				ok := mc.sendImm(nil)
				if !ok {
					return
				}
			} else {
				return
			}
		case data := <-mc.buf:
			cancel()
			ok := mc.sendImm(data)
			if !ok {
				return
			}
		}
	}
}

func (mc *MessageConn) Send(data []byte) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(SendDeadLine))
	select {
	case mc.buf <- data:
		break
	case <-ctx.Done():
		logger.Logger.Info("Send time out, drop it", "remote_addr", mc.remoteAddr, "channel", mc.channel)
	}
	cancel()
}

func (mq *MessageQueue) Send(channel string, data []byte) {
	mq.connPoolLock.RLock()
	defer mq.connPoolLock.RUnlock()
	cur, ok := mq.connPool[channel]
	logger.Logger.Info("Send data to channel", "channel", channel, "data", len(data))
	if !ok || cur == nil {
		logger.Logger.Warn("No listener", "channel", channel)
		return
	}
	for _, conn := range cur {
		conn.Send(data)
	}
}

func (mc *MessageConn) Shutdown() (err error) {
	mc.cancel()
	return mc.conn.Close()
}

func (mq *MessageQueue) Shutdown() {
	noError := true
	err := mq.server.Shutdown(context.Background())
	if err != nil {
		logger.Logger.Info("Stop gin listener failed", "err", err)
		noError = false
	}
	err = mq.listener.Close()
	if err != nil {
		logger.Logger.Info("Stop tcp listener failed", "err", err)
		noError = false
	}
	mq.connPoolLock.Lock()
	defer mq.connPoolLock.Unlock()
	for channel, conns := range mq.connPool {
		for remoteAddr, conn := range conns {
			err = conn.Shutdown()
			if err != nil {
				logger.Logger.Info("Stop tcp connection failed", "err", err, "remote_addr", remoteAddr, "channel", channel)
				noError = false
			}
		}
	}
	if noError {
		logger.Logger.Info("Stop success")
	}
	return
}
