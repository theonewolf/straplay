#!/usr/bin/env python
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
O_CLOEXEC=02000000



DESC='''straplay -- replays strace captures
    expects output to be formatted a la \'strace -ttt -v -y -xx -s 33554432 -f -o \
strace.log\''''

START_RE= '(\d+)[ ]+(\d+)\.(\d+) '
END_RE  = ' = (?:(\d+)|(-\d+) (.*))'
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

        if etype == 'open':  event = OpenEvent.from_re(groups[4:-3])
        if etype == 'write': event = WriteEvent.from_re(groups[4:-3])
        if etype == 'close': event = CloseEvent.from_re(groups[4:-3])
        if etype == 'dup2':  event = Dup2Event.from_re(groups[4:-3])
        if etype == 'lseek': event = LseekEvent.from_re(groups[4:-3])

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
            ret = os.write(self.fd, self.buf)
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
            raise
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
        ret = None
        try:
            ret = os.close(self.fd)
            if ret == None: ret = 0
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
        except:
            assert self.retval < 0
            errorstr = '%s (%s)' % (errorcode[e.errno], os.strerror(e.errno))
            assert errorstr == self.errorstr
            return
        assert ret == self.retval or ret == None
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
    RE=recompile(START_RE + '''(lseek)\((\d+)<(.*)>, (\d+), (.*)\)''' + END_RE)

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

def read_strace_file(fname):
    with open(fname, 'r') as fd:
        return [l.strip() for l in fd.readlines()]

def parse_strace_data(strace_data):
    events = []
    for l in strace_data:
        event = max(WriteEvent.RE.match(l),
                    CloseEvent.RE.match(l),
                    OpenEvent.RE.match(l),
                    Dup2Event.RE.match(l),
                    LseekEvent.RE.match(l))
        
        if event is not None: events.append(Event.from_re(event))

        if ' open(' in l:  assert type(events[-1]).__name__ == 'OpenEvent' 
        if ' write(' in l: assert type(events[-1]).__name__ == 'WriteEvent'
        if ' close(' in l: assert type(events[-1]).__name__ == 'CloseEvent'
        if ' dup2(' in l: assert type(events[-1]).__name__ == 'Dup2Event'
        if ' lseek(' in l: assert type(events[-1]).__name__ == 'LseekEvent'

    return events

def replay_strace(events):
    lasttime = None
    files = {0 : 'stdout', 1 : 'stdin', 2 : 'stderr'}

    for event in events:
        if DEBUG:
            print 'Running event: %s' % (event)
            print '\tFiles: %s' % (files)
        event.do_event(files)
        if DEBUG: print '\tFiles now: %s' % (files)

if __name__ == '__main__':
    parser = ArgumentParser(description=DESC)
    parser.add_argument('strace_log_file',
                        help='file containing strace output')

    args = parser.parse_args()

    strace_data       = read_strace_file(args.strace_log_file)
    parsed_data       = parse_strace_data(strace_data)

    replay_strace(parsed_data)
