FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 将 requirements.txt 复制到容器中
COPY requirements.txt .

# 安装依赖，使用 --no-cache-dir 减小镜像体积
RUN pip install --no-cache-dir -r requirements.txt

# 将当前目录下的所有文件复制到容器的工作目录中
COPY . .

# 声明容器监听的端口
EXPOSE 3000

# 启动命令
CMD ["python", "app.py"]
