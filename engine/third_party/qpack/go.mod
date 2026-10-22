// 这是一个本地兼容模块：模块路径仍然是 github.com/quic-go/qpack，由引擎的
// go.mod 用 replace 指过来。原因见 ./README.md。
module github.com/quic-go/qpack

go 1.26.0

require golang.org/x/net v0.59.0
