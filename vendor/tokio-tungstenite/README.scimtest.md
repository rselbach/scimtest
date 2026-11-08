Vendored tokio-tungstenite 0.28.0, upstream commit
35d110c24c9d030d1608ec964d70c789dfb27452.

The local change exposes Tungstenite's existing `set_config` method. The hosted
tunnel server raises its message/frame limits after authentication, preserving
frames already buffered during the registration handshake. Recreating the
socket to change limits would discard those bytes. The server transport tests
exercise both the registration limit and pipelined traffic across the change.
