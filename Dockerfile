# 构建阶段
FROM golang:1.24-alpine AS builder

# 安装必要的构建工具
RUN apk add --no-cache gcc musl-dev

# 设置工作目录
WORKDIR /app

# 复制 go.mod 和 go.sum（如果存在）
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=1 GOOS=linux go build -a -o dns-resolve-ping .

# 运行阶段
FROM alpine:3.19

# 安装必要的运行时依赖
RUN apk add --no-cache ca-certificates tzdata sqlite libcap

# 创建非 root 用户
RUN adduser -D -u 1000 appuser

# 创建应用目录和数据目录并设置权限
RUN mkdir -p /app/static /data && \
    chown -R appuser:appuser /app /data

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/dns-resolve-ping .

# 设置二进制文件的 capabilities
RUN setcap cap_net_raw+ep /app/dns-resolve-ping

# 复制配置文件和静态文件
COPY --chown=appuser:appuser config.json domain.txt ./
COPY --chown=appuser:appuser static/ ./static/

# 设置时区为上海
ENV TZ=Asia/Shanghai
ENV DOCKER_CONTAINER=true

# 声明数据卷并确保权限
VOLUME ["/data"]

# 切换到非 root 用户
USER appuser

# 暴露 API 端口
EXPOSE 8080

# 启动应用
CMD ["./dns-resolve-ping"]
