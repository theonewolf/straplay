#!/usr/bin/env python3
# vim:set nospell:



import os
from os import O_APPEND,     \
               O_ASYNC,      \
               O_CREAT,      \
               O_DIRECT,     \
               O_DIRECTORY,  \
               O_EXCL,       \
               O_LARGEFILE,  \
               O_NOATIME,    \
               O_NOCTTY,     \
               O_NOFOLLOW,   \
               O_NONBLOCK,   \
               O_NDELAY,     \
               O_RDONLY,     \
               O_RDWR,       \
               O_SYNC,       \
               O_TRUNC,      \
               O_WRONLY,     \
               SEEK_SET,     \
               SEEK_CUR,     \
               SEEK_END
from errno import errorcode




from argparse import ArgumentParser
from re import compile as recompile



# Not in standard os lib?
# from /usr/include/bits/fcntl-linux.h
O_CLOEXEC=0o02000000
AT_FDCWD=-100



DESC='''straplay -- replays strace captures
    expects output to be formatted a la \'strace -ttt -v -y -xx -s 33554432 -f -o \
strace.log\''''

START_RE  = '''(\d+)[ ]+(\d+)\.(\d+) '''
END_RE    = '''[ ]+= (?:(\d+)|(-\d+) (.*))'''
SOCKET_RE = '''socket:\[\d+\]'''
SOCKET_REC= recompile(SOCKET_RE)
DEBUG=False

class Event(object):
    def __init__(self): pass
    def do_event(self): pass

    @classmethod
    def from_re(cl, match):
        event = None
        groups = match.groups()
        pid, timestamp, microseconds, etype = groups[0:4]
        retval, errval, errorstr = groups[-3:]

        if etype == 'open':   event = OpenEvent.from_re(groups[4:-3])
        if etype == 'write':  event = WriteEvent.from_re(groups[4:-3])
        if etype == 'close':  event = CloseEvent.from_re(groups[4:-3])
        if etype == 'dup2':   event = Dup2Event.from_re(groups[4:-3])
        if etype == 'lseek':  event = LseekEvent.from_re(groups[4:-3])
        if etype == 'fsync':  event = FsyncEvent.from_re(groups[4:-3])
        if etype == 'openat': event = OpenAtEvent.from_re(groups[4:-3])
        if etype == 'read':   event = ReadEvent.from_re(groups[4:-3])
        if etype == 'unlink': event = UnlinkEvent.from_re(groups[4:-3])

        event.pid          = int(pid)
        event.etype        = etype
        event.timestamp    = int(timestamp)
        event.microseconds = int(microseconds)
        event.retval       = int(retval) if retval is not None else int(errval)
        event.errorstr     = errorstr
        return event

    def __str__(self):
        return '%s(<%s>) == %s' % (self.etype, self.fname, str(self.retval))

class WriteEvent(Event):
    # 2945  1429043620.207937 write(1</dev/null>, "\x2b\x7a\xc3\xbf\xb4\x2b\x63\x8e\xc3\x55\xcd\xd5\x8e\x63\x32\x3e\x78\xcd\x23\xca\x47\xa7\xe1\x5d\x73\xa0\xd3\x77\x6e\x81\x8a\x06\x7b\x11\x4c\xf0\x0e\xf9\xea\x76\xc4\x33\x62\x0a\x39\x5f\xfa\xd4\x58\x09\xcc\x40\x8e\x4f\xe3\x1d\x0f\xca\xb7\x53\x10\x22\x02\x51\xa6\x7b\xad\xf6\xf2\xd3\x5b\x65\x58\x8b\x48\xfc\xc1\x50\x3d\x6f\xef\x64\xa0\x92\xb8\xff\x8e\x9f\x10\x58\xd5\x46\x9a\xa5\x3f\xea\xd7\x72\x82\x14\xd4\x9d\xbc\xa8\x14\x18\x8b\x43\xd1\xec\x3c\xaf\x99\x5b\x31\x1c\x1d\x89\x89\x55\xfe\x21\x12\x64\x89\xf2\x87\xbd\x69\x74\x7d\xb0\x4e\xcb\xac\x43\xf2\x82\xf0\xa7\xdb\x1c\x2f\x78\xe2\x61\xd3\xc5\x07\xc4\x76\x8a\x17\xc3\x4e\x46\xd2\x2a\x9b\x7e\xbc\x24\x9b\x6b\x79\x14\x41\xe5\xb9\x96\xda\x7b\x34\x57\x1b\x10\x8f\xca\x01\x52\x18\x06\xe3\xff\x89\x1a\xf5\x88\x9f\xfa\x56\xbc\x6f\x4f\x95\xfc\x44\xd9\x5f\x8c\x2d\x84\xd7\x9e\x1f\x12\x35\x90\x35\xbd\xbc\x58\x4e\xbd\xce\xde\x8b\x0d\x08\xb4\xb0\xe5\xe9\xa0\xde\x47\x49\x2e\x82\xc4\x71\x85\x12\x5e\x3e\x2f\x2f\x8c\xb6\x32\x9f\x4d\x20\x53\x1f\x5d\xa6\xa7\xcf\xac\x98\x2a\xc2\x8a\x1d\xaf\x3d\x81\xf5\xff\x48\xac\x06\x7a\x95\xb9\xf4\x9b\xa6\xb6\x71\x0a\x32\xbc\xa2\xdd\xbd\x0a\x1c\xf6\xf0\x27\x35\x37\x7c\x3a\xe2\x15\xe6\x82\xdd\x6e\xee\x2d\xf5\x45\x0a\xdf\x73\x97\xe7\x8a\xbc\x68\x6e\x74\x4b\x4f\x12\x6d\x23\xbe\xb9\x4a\x94\xf1\x70\xba\x12\x66\x4a\x5e\x14\x3b\xef\x2a\x0c\xf8\xf9\x4e\x25\x8f\x87\xe7\x05\x27\xa9\x86\x4e\x7d\x63\x41\x72\xec\x45\x3a\x55\x43\xc2\x20\x5f\x1f\x3c\xc7\x86\x27\x1a\x13\x02\x2d\xf4\xd7\xf1\x80\xe9\x07\x68\x4f\x14\x11\x8b\x51\xbb\xfd\xa6\x4f\xa6\x25\xf8\x61\x8a\xd4\xa9\xd2\xab\x6d\x7d\x65\xf7\xe2\xc2\x9f\x8b\x68\x00\x6d\x64\x4d\x58\x13\x2e\x25\x58\x62\xc9\x7e\x39\x1a\x6c\x01\xa6\x35\x77\xd8\x11\xe5\xfb\x38\xcb\x35\x8b\xe6\xde\x7e\x17\xf1\x23\x8d\xc0\xd1\x71\x9e\x89\x61\x8e\x58\x18\x0b\x8f\x90\xa9\x43\x99\x95\x25\x30\x7c\x05\x83\x30\xb3\x28\xbb\x04\x02\x67\xda\xb0\x46\x97\xb9\x67\x4e\xf5\x04\x53\x87\xac\x3b\x7f\xe9\x73\x97\xb0\x8f\x36\x90\x69\xb1\xf5\xf2\xec\xb2\xfe\xee\x53\x82\xdc\x07\xf5\xe0\xed\x12\x8d\xe4\x6d\xd5\xca\x3d\xf9\xf4\x38\xa5\xec\xcb\xc9\x1a\xb3\x87\xc7\x22\x6c", 512) = 512
    RE=recompile(START_RE + '''(write)\((\d+)\<(.*)\>, (".*"), (\d+)\)''' + END_RE)

    def __init__(self, fd, fname, buf, size):
        super(Event, self)

        self.fd = fd
        self.fname = fname
        self.buf = buf
        self.size = size

    def do_event(self, files):
        ret = None
        try:
            ret = os.write(self.fd, bytes(self.buf, 'latin1'))
        except Exception as e:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval

    @classmethod
    def from_re(cl, groups):
        assert len(groups) == 4

        fd, fname, buf, size = groups

        fd   = int(fd)
        buf  = eval(buf)
        size = int(size)

        assert len(buf) == size

        return WriteEvent(fd, fname, buf, size)

    def __str__(self):
        return '%s(%d<%s>)' % (self.etype, self.fd, self.fname)

class UnlinkEvent(Event):
    # 9846  1429764497.258941 unlink("\x2f\x68\x6f\x6d\x65\x2f\x77\x6f\x6c\x66\x2f\x44\x72\x6f\x70\x62\x6f\x78\x2f\x50\x72\x6f\x6a\x65\x63\x74\x73\x2f\x73\x74\x72\x61\x70\x6c\x61\x79\x2f\x73\x72\x63\x2f\x74\x65\x73\x74\x2f\x74\x65\x73\x74\x2e\x64\x62\x2d\x6a\x6f\x75\x72\x6e\x61\x6c") = 0
    RE=recompile(START_RE + '''(unlink)\((".*")\)''' + END_RE)

    def __init__(self, fname):
        super(Event, self)
        
        self.fname = fname

    def do_event(self, files):
        ret = None
        try:
            ret = os.unlink(self.fname)
            if ret is None: ret = 0
        except Exception as e:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval

    @classmethod
    def from_re(cl, groups):
        assert len(groups) == 1

        fname = eval(groups[0])

        return UnlinkEvent(fname)

    def __str__(self):
        return '%s("%s")' % (self.etype, self.fname)

class ReadEvent(Event):
    # 309   1429760134.551941 read(5</etc/localtime>, "\x54\x5a\x69\x66\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\xeb\x00\x00\x00\x04\x00\x00\x00\x10\x9e\xa6\x1e\x70\x9f\xba\xeb\x60\xa0\x86\x00\x70\xa1\x9a\xcd\x60\xa2\x65\xe2\x70\xa3\x83\xe9\xe0\xa4\x6a\xae\x70\xa5\x35\xa7\x60\xa6\x53\xca\xf0\xa7\x15\x89\x60\xa8\x33\xac\xf0\xa8\xfe\xa5\xe0\xaa\x13\x8e\xf0\xaa\xde\x87\xe0\xab\xf3\x70\xf0\xac\xbe\x69\xe0\xad\xd3\x52\xf0\xae\x9e\x4b\xe0\xaf\xb3\x34\xf0\xb0\x7e\x2d\xe0\xb1\x9c\x51\x70\xb2\x67\x4a\x60\xb3\x7c\x33\x70\xb4\x47\x2c\x60\xb5\x5c\x15\x70\xb6\x27\x0e\x60\xb7\x3b\xf7\x70\xb8\x06\xf0\x60\xb9\x1b\xd9\x70\xb9\xe6\xd2\x60\xbb\x04\xf5\xf0\xbb\xc6\xb4\x60\xbc\xe4\xd7\xf0\xbd\xaf\xd0\xe0\xbe\xc4\xb9\xf0\xbf\x8f\xb2\xe0\xc0\xa4\x9b\xf0\xc1\x6f\x94\xe0\xc2\x84\x7d\xf0\xc3\x4f\x76\xe0\xc4\x64\x5f\xf0\xc5\x2f\x58\xe0\xc6\x4d\x7c\x70\xc7\x0f\x3a\xe0\xc8\x2d\x5e\x70\xc8\xf8\x57\x60\xca\x0d\x40\x70\xca\xd8\x39\x60\xcb\x88\xf0\x70\xd2\x23\xf4\x70\xd2\x60\xfb\xe0\xd3\x75\xe4\xf0\xd4\x40\xdd\xe0\xd5\x55\xc6\xf0\xd6\x20\xbf\xe0\xd7\x35\xa8\xf0\xd8\x00\xa1\xe0\xd9\x15\x8a\xf0\xd9\xe0\x83\xe0\xda\xfe\xa7\x70\xdb\xc0\x65\xe0\xdc\xde\x89\x70\xdd\xa9\x82\x60\xde\xbe\x6b\x70\xdf\x89\x64\x60\xe0\x9e\x4d\x70\xe1\x69\x46\x60\xe2\x7e\x2f\x70\xe3\x49\x28\x60\xe4\x5e\x11\x70\xe5\x57\x2e\xe0\xe6\x47\x2d\xf0\xe7\x37\x10\xe0\xe8\x27\x0f\xf0\xe9\x16\xf2\xe0\xea\x06\xf1\xf0\xea\xf6\xd4\xe0\xeb\xe6\xd3\xf0\xec\xd6\xb6\xe0\xed\xc6\xb5\xf0\xee\xbf\xd3\x60\xef\xaf\xd2\x70\xf0\x9f\xb5\x60\xf1\x8f\xb4\x70\xf2\x7f\x97\x60\xf3\x6f\x96\x70\xf4\x5f\x79\x60\xf5\x4f\x78\x70\xf6\x3f\x5b\x60\xf7\x2f\x5a\x70\xf8\x28\x77\xe0\xf9\x0f\x3c\x70\xfa\x08\x59\xe0\xfa\xf8\x58\xf0\xfb\xe8\x3b\xe0\xfc\xd8\x3a\xf0\xfd\xc8\x1d\xe0\xfe\xb8\x1c\xf0\xff\xa7\xff\xe0\x00\x97\xfe\xf0\x01\x87\xe1\xe0\x02\x77\xe0\xf0\x03\x70\xfe\x60\x04\x60\xfd\x70\x05\x50\xe0\x60\x06\x40\xdf\x70\x07\x30\xc2\x60\x07\x8d\x19\x70\x09\x10\xa4\x60\x09\xad\x94\xf0\x0a\xf0\x86\x60\x0b\xe0\x85\x70\x0c\xd9\xa2\xe0\x0d\xc0\x67\x70\x0e\xb9\x84\xe0\x0f\xa9\x83\xf0\x10\x99\x66\xe0\x11\x89\x65\xf0\x12\x79\x48\xe0\x13\x69\x47\xf0\x14\x59\x2a\xe0\x15\x49\x29\xf0\x16\x39\x0c\xe0\x17\x29\x0b\xf0\x18\x22\x29\x60\x19\x08\xed\xf0\x1a\x02\x0b\x60\x1a\xf2\x0a\x70\x1b\xe1\xed\x60\x1c\xd1\xec\x70\x1d\xc1\xcf\x60\x1e\xb1\xce\x70\x1f\xa1\xb1\x60\x20\x76\x00\xf0\x21\x81\x93\x60\x22\x55\xe2\xf0\x23\x6a\xaf\xe0\x24\x35\xc4\xf0\x25\x4a\x91\xe0\x26\x15\xa6\xf0\x27\x2a\x73\xe0\x27\xfe\xc3\x70\x29\x0a\x55\xe0\x29\xde\xa5\x70\x2a\xea\x37\xe0\x2b\xbe\x87\x70\x2c\xd3\x54\x60\x2d\x9e\x69\x70\x2e\xb3\x36\x60\x2f\x7e\x4b\x70\x30\x93\x18\x60\x31\x67\x67\xf0\x32\x72\xfa\x60\x33\x47\x49\xf0\x34\x52\xdc\x60\x35\x27\x2b\xf0\x36\x32\xbe\x60\x37\x07\x0d\xf0\x38\x1b\xda\xe0\x38\xe6\xef\xf0\x39\xfb\xbc\xe0\x3a\xc6\xd1\xf0\x3b\xdb\x9e\xe0\x3c\xaf\xee\x70\x3d\xbb\x80\xe0\x3e\x8f\xd0\x70\x3f\x9b\x62\xe0\x40\x6f\xb2\x70\x41\x84\x7f\x60\x42\x4f\x94\x70\x43\x64\x61\x60\x44\x2f\x76\x70\x45\x44\x43\x60\x45\xf3\xa8\xf0\x47\x2d\x5f\xe0\x47\xd3\x8a\xf0\x49\x0d\x41\xe0\x49\xb3\x6c\xf0\x4a\xed\x23\xe0\x4b\x9c\x89\x70\x4c\xd6\x40\x60\x4d\x7c\x6b\x70\x4e\xb6\x22\x60\x4f\x5c\x4d\x70\x50\x96\x04\x60\x51\x3c\x2f\x70\x52\x75\xe6\x60\x53\x1c\x11\x70\x54\x55\xc8\x60\x54\xfb\xf3\x70\x56\x35\xaa\x60\x56\xe5\x0f\xf0\x58\x1e\xc6\xe0\x58\xc4\xf1\xf0\x59\xfe\xa8\xe0\x5a\xa4\xd3\xf0\x5b\xde\x8a\xe0\x5c\x84\xb5\xf0\x5d\xbe\x6c\xe0\x5e\x64\x97\xf0\x5f\x9e\x4e\xe0\x60\x4d\xb4\x70\x61\x87\x6b\x60\x62\x2d\x96\x70\x63\x67\x4d\x60\x64\x0d\x78\x70\x65\x47\x2f\x60\x65\xed\x5a\x70\x67\x27\x11\x60\x67\xcd\x3c\x70\x69\x06\xf3\x60\x69\xad\x1e\x70\x6a\xe6\xd5\x60\x6b\x96\x3a\xf0\x6c\xcf\xf1\xe0\x6d\x76\x1c\xf0\x6e\xaf\xd3\xe0\x6f\x55\xfe\xf0\x70\x8f\xb5\xe0\x71\x35\xe0\xf0\x72\x6f\x97\xe0\x73\x15\xc2\xf0\x74\x4f\x79\xe0\x74\xfe\xdf\x70\x76\x38\x96\x60\x76\xde\xc1\x70\x78\x18\x78\x60\x78\xbe\xa3\x70\x79\xf8\x5a\x60\x7a\x9e\x85\x70\x7b\xd8\x3c\x60\x7c\x7e\x67\x70\x7d\xb8\x1e\x60\x7e\x5e\x49\x70\x7f\x98\x00\x60\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x02\x03\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\xff\xff\xc7\xc0\x01\x00\xff\xff\xb9\xb0\x00\x04\xff\xff\xc7\xc0\x01\x08\xff\xff\xc7\xc0\x01\x0c\x45\x44\x54\x00\x45\x53\x54\x00\x45\x57\x54\x00\x45\x50\x54\x00\x00\x00\x00\x01\x00\x00\x00\x01\x54\x5a\x69\x66\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\xec\x00\x00\x00\x05\x00\x00\x00\x14\xff\xff\xff\xff\x5e\x03\xf0\x90\xff\xff\xff\xff\x9e\xa6\x1e\x70\xff\xff\xff\xff\x9f\xba\xeb\x60\xff\xff\xff\xff\xa0\x86\x00\x70\xff\xff\xff\xff\xa1\x9a\xcd\x60\xff\xff\xff\xff\xa2\x65\xe2\x70\xff\xff\xff\xff\xa3\x83\xe9\xe0\xff\xff\xff\xff\xa4\x6a\xae\x70\xff\xff\xff\xff\xa5\x35\xa7\x60\xff\xff\xff\xff\xa6\x53\xca\xf0\xff\xff\xff\xff\xa7\x15\x89\x60\xff\xff\xff\xff\xa8\x33\xac\xf0\xff\xff\xff\xff\xa8\xfe\xa5\xe0\xff\xff\xff\xff\xaa\x13\x8e\xf0\xff\xff\xff\xff\xaa\xde\x87\xe0\xff\xff\xff\xff\xab\xf3\x70\xf0\xff\xff\xff\xff\xac\xbe\x69\xe0\xff\xff\xff\xff\xad\xd3\x52\xf0\xff\xff\xff\xff\xae\x9e\x4b\xe0\xff\xff\xff\xff\xaf\xb3\x34\xf0\xff\xff\xff\xff\xb0\x7e\x2d\xe0\xff\xff\xff\xff\xb1\x9c\x51\x70\xff\xff\xff\xff\xb2\x67\x4a\x60\xff\xff\xff\xff\xb3\x7c\x33\x70\xff\xff\xff\xff\xb4\x47\x2c\x60\xff\xff\xff\xff\xb5\x5c\x15\x70\xff\xff\xff\xff\xb6\x27\x0e\x60\xff\xff\xff\xff\xb7\x3b\xf7\x70\xff\xff\xff\xff\xb8\x06\xf0\x60\xff\xff\xff\xff\xb9\x1b\xd9\x70\xff\xff\xff\xff\xb9\xe6\xd2\x60\xff\xff\xff\xff\xbb\x04\xf5\xf0\xff\xff\xff\xff\xbb\xc6\xb4\x60\xff\xff\xff\xff\xbc\xe4\xd7\xf0\xff\xff\xff\xff\xbd\xaf\xd0\xe0\xff\xff\xff\xff\xbe\xc4\xb9\xf0\xff\xff\xff\xff\xbf\x8f\xb2\xe0\xff\xff\xff\xff\xc0\xa4\x9b\xf0\xff\xff\xff\xff\xc1\x6f\x94\xe0\xff\xff\xff\xff\xc2\x84\x7d\xf0\xff\xff\xff\xff\xc3\x4f\x76\xe0\xff\xff\xff\xff\xc4\x64\x5f\xf0\xff\xff\xff\xff\xc5\x2f\x58\xe0\xff\xff\xff\xff\xc6\x4d\x7c\x70\xff\xff\xff\xff\xc7\x0f\x3a\xe0\xff\xff\xff\xff\xc8\x2d\x5e\x70\xff\xff\xff\xff\xc8\xf8\x57\x60\xff\xff\xff\xff\xca\x0d\x40\x70\xff\xff\xff\xff\xca\xd8\x39\x60\xff\xff\xff\xff\xcb\x88\xf0\x70\xff\xff\xff\xff\xd2\x23\xf4\x70\xff\xff\xff\xff\xd2\x60\xfb\xe0\xff\xff\xff\xff\xd3\x75\xe4\xf0\xff\xff\xff\xff\xd4\x40\xdd\xe0\xff\xff\xff\xff\xd5\x55\xc6\xf0\xff\xff\xff\xff\xd6\x20\xbf\xe0\xff\xff\xff\xff\xd7\x35\xa8\xf0\xff\xff\xff\xff\xd8\x00\xa1\xe0\xff\xff\xff\xff\xd9\x15\x8a\xf0\xff\xff\xff\xff\xd9\xe0\x83\xe0\xff\xff\xff\xff\xda\xfe\xa7\x70\xff\xff\xff\xff\xdb\xc0\x65\xe0\xff\xff\xff\xff\xdc\xde\x89\x70\xff\xff\xff\xff\xdd\xa9\x82\x60\xff\xff\xff\xff\xde\xbe\x6b\x70\xff\xff\xff\xff\xdf\x89\x64\x60\xff\xff\xff\xff\xe0\x9e\x4d\x70\xff\xff\xff\xff\xe1\x69\x46\x60\xff\xff\xff\xff\xe2\x7e\x2f\x70\xff\xff\xff\xff\xe3\x49\x28\x60\xff\xff\xff\xff\xe4\x5e\x11\x70\xff\xff\xff\xff\xe5\x57\x2e\xe0\xff\xff\xff\xff\xe6\x47\x2d\xf0\xff\xff\xff\xff\xe7\x37\x10\xe0\xff\xff\xff\xff\xe8\x27\x0f\xf0\xff\xff\xff\xff\xe9\x16\xf2\xe0\xff\xff\xff\xff\xea\x06\xf1\xf0\xff\xff\xff\xff\xea\xf6\xd4\xe0\xff\xff\xff\xff\xeb\xe6\xd3\xf0\xff\xff\xff\xff\xec\xd6\xb6\xe0\xff\xff\xff\xff\xed\xc6\xb5\xf0\xff\xff\xff\xff\xee\xbf\xd3\x60\xff\xff\xff\xff\xef\xaf\xd2\x70\xff\xff\xff\xff\xf0\x9f\xb5\x60\xff\xff\xff\xff\xf1\x8f\xb4\x70\xff\xff\xff\xff\xf2\x7f\x97\x60\xff\xff\xff\xff\xf3\x6f\x96\x70\xff\xff\xff\xff\xf4\x5f\x79\x60\xff\xff\xff\xff\xf5\x4f\x78\x70\xff\xff\xff\xff\xf6\x3f\x5b\x60\xff\xff\xff\xff\xf7\x2f\x5a\x70\xff\xff\xff\xff\xf8\x28\x77\xe0\xff\xff\xff\xff\xf9\x0f\x3c\x70\xff\xff\xff\xff\xfa\x08\x59\xe0\xff\xff\xff\xff\xfa\xf8\x58\xf0\xff\xff\xff\xff\xfb\xe8\x3b\xe0\xff\xff\xff\xff\xfc\xd8\x3a\xf0\xff\xff\xff\xff\xfd\xc8\x1d\xe0\xff\xff\xff\xff\xfe\xb8\x1c\xf0\xff\xff\xff\xff\xff\xa7\xff\xe0\x00\x00\x00\x00\x00\x97\xfe\xf0\x00\x00\x00\x00\x01\x87\xe1\xe0\x00\x00\x00\x00\x02\x77\xe0\xf0\x00\x00\x00\x00\x03\x70\xfe\x60\x00\x00\x00\x00\x04\x60\xfd\x70\x00\x00\x00\x00\x05\x50\xe0\x60\x00\x00\x00\x00\x06\x40\xdf\x70\x00\x00\x00\x00\x07\x30\xc2\x60\x00\x00\x00\x00\x07\x8d\x19\x70\x00\x00\x00\x00\x09\x10\xa4\x60\x00\x00\x00\x00\x09\xad\x94\xf0\x00\x00\x00\x00\x0a\xf0\x86\x60\x00\x00\x00\x00\x0b\xe0\x85\x70\x00\x00\x00\x00\x0c\xd9\xa2\xe0\x00\x00\x00\x00\x0d\xc0\x67\x70\x00\x00\x00\x00\x0e\xb9\x84\xe0\x00\x00\x00\x00\x0f\xa9\x83\xf0\x00\x00\x00\x00\x10\x99\x66\xe0\x00\x00\x00\x00\x11\x89\x65\xf0\x00\x00\x00\x00\x12\x79\x48\xe0\x00\x00\x00\x00\x13\x69\x47\xf0\x00\x00\x00\x00\x14\x59\x2a\xe0\x00\x00\x00\x00\x15\x49\x29\xf0\x00\x00\x00\x00\x16\x39\x0c\xe0\x00\x00\x00\x00\x17\x29\x0b\xf0\x00\x00\x00\x00\x18\x22\x29\x60\x00\x00\x00\x00\x19\x08\xed\xf0\x00\x00\x00\x00\x1a\x02\x0b\x60\x00\x00\x00\x00\x1a\xf2\x0a\x70\x00\x00\x00\x00\x1b\xe1\xed\x60\x00\x00\x00\x00\x1c\xd1\xec\x70\x00\x00\x00\x00\x1d\xc1\xcf\x60\x00\x00\x00\x00\x1e\xb1\xce\x70\x00\x00\x00\x00\x1f\xa1\xb1\x60\x00\x00\x00\x00\x20\x76\x00\xf0\x00\x00\x00\x00\x21\x81\x93\x60\x00\x00\x00\x00\x22\x55\xe2\xf0\x00\x00\x00\x00\x23\x6a\xaf\xe0\x00\x00\x00\x00\x24\x35\xc4\xf0\x00\x00\x00\x00\x25\x4a\x91\xe0\x00\x00\x00\x00\x26\x15\xa6\xf0\x00\x00\x00\x00\x27\x2a\x73\xe0\x00\x00\x00\x00\x27\xfe\xc3\x70\x00\x00\x00\x00\x29\x0a\x55\xe0\x00\x00\x00\x00\x29\xde\xa5\x70\x00\x00\x00\x00\x2a\xea\x37\xe0\x00\x00\x00\x00\x2b\xbe\x87\x70\x00\x00\x00\x00\x2c\xd3\x54\x60\x00\x00\x00\x00\x2d\x9e\x69\x70\x00\x00\x00\x00\x2e\xb3\x36\x60\x00\x00\x00\x00\x2f\x7e\x4b\x70\x00\x00\x00\x00\x30\x93\x18\x60\x00\x00\x00\x00\x31\x67\x67\xf0\x00\x00\x00\x00\x32\x72\xfa\x60\x00\x00\x00\x00\x33\x47\x49\xf0\x00\x00\x00\x00\x34\x52\xdc\x60\x00\x00\x00\x00\x35\x27\x2b\xf0\x00\x00\x00\x00\x36\x32\xbe\x60\x00\x00\x00\x00\x37\x07\x0d\xf0\x00\x00\x00\x00\x38\x1b\xda\xe0\x00\x00\x00\x00\x38\xe6\xef\xf0\x00\x00\x00\x00\x39\xfb\xbc\xe0\x00\x00\x00\x00\x3a\xc6\xd1\xf0\x00\x00\x00\x00\x3b\xdb\x9e\xe0\x00\x00\x00\x00\x3c\xaf\xee\x70\x00\x00\x00\x00\x3d\xbb\x80\xe0\x00\x00\x00\x00\x3e\x8f\xd0\x70\x00\x00\x00\x00\x3f\x9b\x62\xe0\x00\x00\x00\x00\x40\x6f\xb2\x70\x00\x00\x00\x00\x41\x84\x7f\x60\x00\x00\x00\x00\x42\x4f\x94\x70\x00\x00\x00\x00\x43\x64\x61\x60\x00\x00\x00\x00\x44\x2f\x76\x70\x00\x00\x00\x00\x45\x44\x43\x60\x00\x00\x00\x00\x45\xf3\xa8\xf0\x00\x00\x00\x00\x47\x2d\x5f\xe0\x00\x00\x00\x00\x47\xd3\x8a\xf0\x00\x00\x00\x00\x49\x0d\x41\xe0\x00\x00\x00\x00\x49\xb3\x6c\xf0\x00\x00\x00\x00\x4a\xed\x23\xe0\x00\x00\x00\x00\x4b\x9c\x89\x70\x00\x00\x00\x00\x4c\xd6\x40\x60\x00\x00\x00\x00\x4d\x7c\x6b\x70\x00\x00\x00\x00\x4e\xb6\x22\x60\x00\x00\x00\x00\x4f\x5c\x4d\x70\x00\x00\x00\x00\x50\x96\x04\x60\x00\x00\x00\x00\x51\x3c\x2f\x70\x00\x00\x00\x00\x52\x75\xe6\x60\x00\x00\x00\x00\x53\x1c\x11\x70\x00\x00\x00\x00\x54\x55\xc8\x60\x00\x00\x00\x00\x54\xfb\xf3\x70\x00\x00\x00\x00\x56\x35\xaa\x60\x00\x00\x00\x00\x56\xe5\x0f\xf0\x00\x00\x00\x00\x58\x1e\xc6\xe0\x00\x00\x00\x00\x58\xc4\xf1\xf0\x00\x00\x00\x00\x59\xfe\xa8\xe0\x00\x00\x00\x00\x5a\xa4\xd3\xf0\x00\x00\x00\x00\x5b\xde\x8a\xe0\x00\x00\x00\x00\x5c\x84\xb5\xf0\x00\x00\x00\x00\x5d\xbe\x6c\xe0\x00\x00\x00\x00\x5e\x64\x97\xf0\x00\x00\x00\x00\x5f\x9e\x4e\xe0\x00\x00\x00\x00\x60\x4d\xb4\x70\x00\x00\x00\x00\x61\x87\x6b\x60\x00\x00\x00\x00\x62\x2d\x96\x70\x00\x00\x00\x00\x63\x67\x4d\x60\x00\x00\x00\x00\x64\x0d\x78\x70\x00\x00\x00\x00\x65\x47\x2f\x60\x00\x00\x00\x00\x65\xed\x5a\x70\x00\x00\x00\x00\x67\x27\x11\x60\x00\x00\x00\x00\x67\xcd\x3c\x70\x00\x00\x00\x00\x69\x06\xf3\x60\x00\x00\x00\x00\x69\xad\x1e\x70\x00\x00\x00\x00\x6a\xe6\xd5\x60\x00\x00\x00\x00\x6b\x96\x3a\xf0\x00\x00\x00\x00\x6c\xcf\xf1\xe0\x00\x00\x00\x00\x6d\x76\x1c\xf0\x00\x00\x00\x00\x6e\xaf\xd3\xe0\x00\x00\x00\x00\x6f\x55\xfe\xf0\x00\x00\x00\x00\x70\x8f\xb5\xe0\x00\x00\x00\x00\x71\x35\xe0\xf0\x00\x00\x00\x00\x72\x6f\x97\xe0\x00\x00\x00\x00\x73\x15\xc2\xf0\x00\x00\x00\x00\x74\x4f\x79\xe0\x00\x00\x00\x00\x74\xfe\xdf\x70\x00\x00\x00\x00\x76\x38\x96\x60\x00\x00\x00\x00\x76\xde\xc1\x70\x00\x00\x00\x00\x78\x18\x78\x60\x00\x00\x00\x00\x78\xbe\xa3\x70\x00\x00\x00\x00\x79\xf8\x5a\x60\x00\x00\x00\x00\x7a\x9e\x85\x70\x00\x00\x00\x00\x7b\xd8\x3c\x60\x00\x00\x00\x00\x7c\x7e\x67\x70\x00\x00\x00\x00\x7d\xb8\x1e\x60\x00\x00\x00\x00\x7e\x5e\x49\x70\x00\x00\x00\x00\x7f\x98\x00\x60\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x03\x04\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\x01\x02\xff\xff\xba\x9e\x00\x00\xff\xff\xc7\xc0\x01\x04\xff\xff\xb9\xb0\x00\x08\xff\xff\xc7\xc0\x01\x0c\xff\xff\xc7\xc0\x01\x10\x4c\x4d\x54\x00\x45\x44\x54\x00\x45\x53\x54\x00\x45\x57\x54\x00\x45\x50\x54\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x0a\x45\x53\x54\x35\x45\x44\x54\x2c\x4d\x33\x2e\x32\x2e\x30\x2c\x4d\x31\x31\x2e\x31\x2e\x30\x0a", 4096) = 3519
    RE=recompile(START_RE + '''(read)\((\d+)\<(.*)\>, ".*", (\d+)\)''' + END_RE)

    def __init__(self, fd, fname, size):
        super(Event, self)

        self.fd = fd
        self.fname = fname
        self.size = size

    def do_event(self, files):
        ret = None
        try:
            ret = os.read(self.fd, self.size)
        except Exception as e:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert len(ret) == self.retval

    @classmethod
    def from_re(cl, groups):
        assert len(groups) == 3

        fd, fname, size = groups

        fd    = int(fd)
        size  = int(size)

        return ReadEvent(fd, fname, size) 

    def __str__(self):
        return '%s(%d<%s>)' % (self.etype, self.fd, self.fname)

class OpenAtEvent(Event):
    # 5271  1429507989.673227 openat(AT_FDCWD, "\x2f\x68\x6f\x6d\x65\x2f\x77\x6f\x6c\x66\x2f\x2e\x6c\x6f\x63\x61\x6c\x2f\x6c\x69\x62\x2f\x70\x79\x74\x68\x6f\x6e\x32\x2e\x37\x2f\x73\x69\x74\x65\x2d\x70\x61\x63\x6b\x61\x67\x65\x73", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 4
    RE=recompile(START_RE + '''(openat)\((.*), (".*"), (?:(.*)|(.*), (.*))\)''' + END_RE)

    def __init__(self, dirfd, fname, flags, mode=None):
        super(Event, self)

        self.dirfd = dirfd
        self.fname = fname
        self.flags = flags
        self.mode = mode

    def do_event(self, files):
        ret = None
        try:
            if self.mode is not None:
                ret = os.open(self.fname, self.flags, self.mode, dir_fd = self.dirfd)
            else:
                ret = os.open(self.fname, self.flags, dir_fd = self.dirfd)
        except Exception as e:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval
        files[ret] = self.fname

    @classmethod
    def from_re(cl, groups):
        assert len(groups) == 5

        dirfd, fname, flags, flags2, mode = groups
        dirfd = eval(dirfd)
        fname = eval(fname)
        flags = eval(flags) if flags is not None else eval(flags2)
        if mode is not None: mode = int(mode, 8)

        return OpenAtEvent(dirfd, fname, flags, mode)

class OpenEvent(Event):
    # 2945  1429043620.207773 open("\x2f\x64\x65\x76\x2f\x6e\x75\x6c\x6c", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
    RE=recompile(START_RE + '''(open)\((".*"), (?:(.*), (.*)|(.*))\)''' + END_RE)

    def __init__(self, fname, flags, mode, flags2):
        super(Event, self)

        self.fname    = fname
        self.flags    = flags if flags is not None else flags2
        self.mode     = mode

    def do_event(self, files):
        ret = None
        try:
            if self.mode is not None:
                ret = os.open(self.fname, self.flags, self.mode)
            else:
                ret = os.open(self.fname, self.flags)
        except Exception as e:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval
        files[ret] = self.fname

    @classmethod
    def from_re(cl, groups):
        assert len(groups) == 4
        fname, flags, mode, flags2 = groups

        fname = eval(fname)
        flags = eval(flags) if flags is not None else eval(flags2)
        if mode is not None: mode = int(mode, 8)

        return OpenEvent(fname, flags, mode, flags2)

class CloseEvent(Event):
    # 2945  1429043620.209347 close(1</dev/null>) = 0
    RE=recompile(START_RE + '''(close)\((\d+)\<(.*)\>\)''' + END_RE)

    def __init__(self, fd, fname):
        super(Event, self)

        self.fd     = fd
        self.fname  = fname

    def do_event(self, files):
        if SOCKET_REC.match(self.fname) is not None: return
        ret = None
        try:
            ret = os.close(self.fd)
            if ret is None: ret = 0
        except Exception as e:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval
        del files[self.fd]

    @classmethod
    def from_re(cl, groups):
        assert len(groups) == 2

        fd, fname = groups
        fd = int(fd)

        return CloseEvent(fd, fname)

    def __str__(self):
        return '%s(%d<%s>)' % (self.etype, self.fd, self.fname)

class Dup2Event(Event):
    #2945  1429043620.207665 dup2(3</home/wolf/Dropbox/Projects/strace-replay/testfile>, 0</dev/pts/37>) = 0
    RE=recompile(START_RE + '''(dup2)\((?:(\d+)<(.*)>|(\d+)), (?:(\d+)<(.*)>|(\d+))\)''' + END_RE)

    def __init__(self, fd1, fname1, fd2, fname2):
        super(Event, self)

        self.fd1 = fd1
        self.fd2 = fd2
        self.fname1 = fname1
        self.fname2 = fname2

    def do_event(self, files):
        ret = None
        try:
            ret = os.dup2(self.fd1, self.fd2)
            if ret is None: ret = 0
        except:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval
        files[self.fd2] = self.fname1

    @classmethod
    def from_re(cl, groups):
        fd1, fname1, fd1_lone, fd2, fname2, fd2_lone = groups

        fd1 = int(fd1) if fd1 is not None else int(fd1_lone)
        fd2 = int(fd2) if fd2 is not None else int(fd2_lone)

        return Dup2Event(fd1, fname1, fd2, fname2)

    def __str__(self):
        return '%s(%d<%s>, %d<%s>)' % (self.etype, self.fd1, self.fname1,
                                                   self.fd2, self.fname2)

class LseekEvent(Event):
    #2945  1429043620.207743 lseek(0</home/wolf/Dropbox/Projects/strace-replay/testfile>, 0, SEEK_CUR) = 0
    RE=recompile(START_RE + '''(lseek)\((\d+)<(.*)>, (-?\d+), (.*)\)''' + END_RE)

    def __init__(self, fd, fname, position, flags):
        super(Event, self)

        self.fd = fd
        self.fname = fname
        self.position = position
        self.flags = flags

    def do_event(self, files):
        ret = None
        try:
            ret = os.lseek(self.fd, self.position, self.flags)
        except Exception as e:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval
    
    @classmethod
    def from_re(cl, groups):
        fd, fname, position, flags = groups

        fd = int(fd)
        position = int(position)
        flags = eval(flags)

        return LseekEvent(fd, fname, position, flags)

    def __str__(self):
        return '%s(%d<%s>, %d, %d)' % (self.etype, self.fd, self.fname,
                                       self.position, self.flags)

class FsyncEvent(Event):
    #9775  1429499443.608683 fsync(3</tmp/test.db>) = 0
    RE=recompile(START_RE + '''(fsync)\((\d+)<(.*)>\)''' + END_RE)

    def __init__(self, fd, fname):
        super(Event, self)

        self.fd = fd
        self.fname = fname

    def do_event(self, files):
        ret = None
        try:
            ret = os.fsync(self.fd)
            if ret is None: ret = 0
        except Exception as e:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval

    @classmethod
    def from_re(cl, groups):
        fd, fname = groups

        fd = int(fd)

        return FsyncEvent(fd, fname)

    def __str__(self):
        return '%s(%d<%s>)' % (self.etype, self.fd, self.fname)

def read_strace_file(fname):
    with open(fname, 'r') as fd:
        return [l.strip() for l in fd.readlines()]

def parse_strace_data(strace_data):
    etypes = [WriteEvent, CloseEvent, OpenEvent, Dup2Event, LseekEvent,
              FsyncEvent, OpenAtEvent, ReadEvent, UnlinkEvent]
    events = []

    for l in strace_data:
        event = None

        for e in etypes:
            event = e.RE.match(l)
            if event is not None:
                events.append(Event.from_re(event))

        if ' open('  in l:  assert type(events[-1]).__name__ == 'OpenEvent' 
        if ' write(' in l:  assert type(events[-1]).__name__ == 'WriteEvent'
        if ' close(' in l:  assert type(events[-1]).__name__ == 'CloseEvent'
        if ' dup2('  in l:  assert type(events[-1]).__name__ == 'Dup2Event'
        if ' lseek(' in l:  assert type(events[-1]).__name__ == 'LseekEvent'
        if ' fsync(' in l:  assert type(events[-1]).__name__ == 'FsyncEvent'
        if ' openat(' in l: assert type(events[-1]).__name__ == 'OpenAtEvent'
        if ' read(' in l:   assert type(events[-1]).__name__ == 'ReadEvent'
        if ' unlink(' in l: assert type(events[-1]).__name__ == 'UnlinkEvent'

    return events

def replay_strace(events):
    lasttime = None
    files = {0 : 'stdout', 1 : 'stdin', 2 : 'stderr'}

    for event in events:
        if DEBUG:
            print('Running event: %s' % (event))
            print('\tFiles: %s' % (files))
        event.do_event(files)
        if DEBUG: print('\tFiles now: %s' % (files))

if __name__ == '__main__':
    parser = ArgumentParser(description=DESC)
    parser.add_argument('strace_log_file',
                        help='file containing strace output')

    args = parser.parse_args()

    strace_data       = read_strace_file(args.strace_log_file)
    parsed_data       = parse_strace_data(strace_data)

    replay_strace(parsed_data)