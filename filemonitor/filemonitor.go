package filemonitor

import (
	"bufio"
	"errors"
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const flags = syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

type FileChan struct {
	Cout chan string
	Cerr chan string
}

type INDescriptors struct {
	fd int
	wd int
}

//FileMonitor ..
type FileMonitor struct {
	operatingList map[string]*INDescriptors
	lock          sync.RWMutex
}

func NewFileMonitor() *FileMonitor {
	f := new(FileMonitor)
	f.Init()
	return f
}

func (fm *FileMonitor) Init() {
	fm.operatingList = make(map[string]*INDescriptors)
	fm.lock = sync.RWMutex{}
}

func (fm *FileMonitor) readOperationList(key string) *INDescriptors {
	fm.lock.RLock()
	defer fm.lock.RUnlock()
	return fm.operatingList[key]
}

func (fm *FileMonitor) writeOperationList(key string, value *INDescriptors) {
	fm.lock.Lock()
	defer fm.lock.Unlock()
	fm.operatingList[key] = value
}

func (fm *FileMonitor) deleteOperationList(key string) {
	fm.lock.Lock()
	defer fm.lock.Unlock()
	delete(fm.operatingList, key)
}

func (fm *FileMonitor) RemoveFile(path string) {
	inDesc := fm.readOperationList(path)
	syscall.InotifyRmWatch(inDesc.fd, uint32(inDesc.wd))
	log.Println("File Removed: ", path)
}

func (fm *FileMonitor) AddFile(path string) (*FileChan, error) {

	err := fm._addFile(path)
	if err != nil {
		return nil, err
	}

	//make our/err channels
	fchan := &FileChan{}
	fchan.Cout = make(chan string, 1000)
	fchan.Cerr = make(chan string)

	go fm.tailLoop(path, fchan)

	return fchan, nil
}

func (fm *FileMonitor) _addFile(path string) error {
	fd, err := syscall.InotifyInit()
	if err != nil {
		return err
	}
	if fd == -1 {
		return errors.New("InotifyInit error")
	}

	wd, _ := syscall.InotifyAddWatch(fd, path, uint32(flags))
	if wd == -1 {
		return errors.New("InotifyAddWatch error")
	}
	inDesc := &INDescriptors{fd, wd}
	fm.writeOperationList(path, inDesc)

	return nil
}

func (fm *FileMonitor) tailLoop(path string, fchan *FileChan) {
	var buffer [syscall.SizeofInotifyEvent * 1000]byte
	var len int
	var err error
	var fi os.FileInfo
	var currentSize int64

	file, err := os.Open(path)
	reader := bufio.NewReader(file)

	//TODO: make it optional
	//read whatever is in the file now:
	err = readLoop(reader, fchan.Cout)
	if err != nil {
		fchan.Cerr <- "read error: " + err.Error()
		return
	}

	for {
		inDesc := fm.readOperationList(path)
		len, err = syscall.Read(inDesc.fd, buffer[0:])

		if err != nil || len == -1 {
			log.Println("Inotify Read error in ", path)
			fchan.Cerr <- "Watcher aborted. Inotify Read error."
			return
		}
		//log.Println("bytes read: ", len)
		if len >= syscall.SizeofInotifyEvent {
			var offset = 0
			for offset < len {
				raw := (*syscall.InotifyEvent)(unsafe.Pointer(&buffer[offset]))
				mask := uint32(raw.Mask)
				offset = offset + int(raw.Len) + syscall.SizeofInotifyEvent

				if mask&syscall.IN_IGNORED == syscall.IN_IGNORED {
					log.Println("IN_IGNORED")
					syscall.Close(inDesc.fd)
					fm.deleteOperationList(path)
					fchan.Cerr <- "Watcher closed. (IN_IGNORED)"
					return
				}
				if mask&syscall.IN_Q_OVERFLOW == syscall.IN_Q_OVERFLOW {
					log.Println("IN_Q_OVERFLOW")
					syscall.Close(inDesc.fd)
					fm.deleteOperationList(path)
					fchan.Cerr <- "Watcher aborted. (IN_Q_OVERFLOW)"
					return
				}
				if mask&syscall.IN_UNMOUNT == syscall.IN_UNMOUNT {
					log.Println("IN_UNMOUNT")
					syscall.Close(inDesc.fd)
					fm.deleteOperationList(path)
					fchan.Cerr <- "Watcher aborted. (IN_UNMOUNT)"
					return
				}
				if mask == syscall.IN_MODIFY {
					//log.Println("IN_MODIFY")

					fi, _ = file.Stat()
					if fi.Size() < currentSize {
						log.Println("file downsized.. resetting")
						file.Seek(0, 2) //set offset to the end of the file
						reader = bufio.NewReader(file)
					}

					err = readLoop(reader, fchan.Cout)
					if err != nil {
						fchan.Cerr <- "read error: " + err.Error()
						return
					}

					fi, _ = file.Stat()
					currentSize = fi.Size()

					continue
				}
				if mask == syscall.IN_ATTRIB || mask == syscall.IN_DELETE_SELF || mask == syscall.IN_MOVE_SELF {
					log.Println("FILE WAS DELETED/MOVED")

					// re-add file
					fm.RemoveFile(path)
					syscall.Close(inDesc.fd)
					fileReAdded := false
					for !fileReAdded {
						time.Sleep(2 * time.Second)
						err = fm._addFile(path)
						if err == nil {
							log.Println("file re-added")
							file, err = os.Open(path)
							if err == nil {
								fileReAdded = true
							}
						}
					}
					reader = bufio.NewReader(file)
					currentSize = 0
					continue
				}

				log.Printf("Unexpected event\n")
				fchan.Cerr <- "Watcher aborted. Unexpected event"
			}
		}
	}
}

func readLoop(reader *bufio.Reader, cout chan<- string) error {
	eof := false
	for !eof {
		bytes, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			log.Println("read error:", err)
			return err
		}
		if err == io.EOF {
			eof = true
		}
		cout <- string(bytes)
	}
	return nil
}
