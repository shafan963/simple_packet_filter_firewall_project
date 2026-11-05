FROM gcc:latest

WORKDIR /app

# Copy all files from this folder into the container
COPY . .

# Compile server.c from the src directory
RUN gcc -Wall -Wextra -O2 src/server.c -o server

# Render uses port 10000 by default
EXPOSE 10000

CMD ["./server"]
