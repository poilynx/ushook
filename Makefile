    CC = cc
CFLAGS = -g
  OBJS = notify.o
TARGET = notify

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(CFLAGS)

clean:
	$(RM) $(TARGET) $(OBJS)
