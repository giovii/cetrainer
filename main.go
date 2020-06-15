package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/TheTitanrain/w32"
	"strings"
	"syscall"
	windows "syscall"
	"time"
	"unsafe"
)

const TH32CS_SNAPPROCESS = 0x00000002
const T = 10

var psapi = windows.NewLazyDLL("psapi.dll")
var (
	procEnumProcesses      = psapi.NewProc("EnumProcesses")
	procEnumProcessModules = psapi.NewProc("EnumProcessModules")
	procGetModuleBaseName  = psapi.NewProc("GetModuleBaseNameW")
	getModuleInformation   = psapi.NewProc("GetModuleInformation")
	getModulefilename      = psapi.NewProc("GetModuleFileNameExA")
	procVirtualProtect     = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtectEx")
	info                   moduleinfo
	handle                 w32.HANDLE
)

type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

type moduleinfo struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

func processes() ([]WindowsProcess, error) {
	handle, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	// get the first process
	err = windows.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}

	results := make([]WindowsProcess, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		err = windows.Process32Next(handle, &entry)
		if err != nil {
			// windows sends ERROR_NO_MORE_FILES on last process
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}
			return nil, err
		}
	}
}

func findProcessByName(processes []WindowsProcess, name string) *WindowsProcess {
	for _, p := range processes {
		if strings.ToLower(p.Exe) == strings.ToLower(name) {
			return &p
		}
	}
	return nil
}

func newWindowsProcess(e *windows.ProcessEntry32) WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		Exe:             syscall.UTF16ToString(e.ExeFile[:end]),
	}
}
func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

func EnumProcessModule(process windows.Handle) (h windows.Handle, err error) {
	var module [1]windows.Handle
	_, err = EnumProcessModules(process, module[:])
	return module[0], err
}

func EnumProcessModules(process windows.Handle, modules []windows.Handle) (n int, err error) {
	var needed int32
	const handleSize = unsafe.Sizeof(modules[0])
	r1, _, e1 := procEnumProcessModules.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&modules[0])),
		handleSize*uintptr(len(modules)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		err = errno(e1)
		return 0, err
	}
	n = int(uintptr(needed) / handleSize)
	return n, nil
}
func GetModuleBaseName(process w32.HANDLE, module windows.Handle, outString *uint16, size uint32) (n int, err error) {
	r1, _, e1 := procGetModuleBaseName.Call(
		uintptr(process),
		uintptr(module),
		uintptr(unsafe.Pointer(outString)),
		uintptr(size),
	)
	if r1 == 0 {
		return 0, errno(e1)
	}
	return int(r1), nil
}

func writeHelper(address int, byteArray []byte) {
	w32.WriteProcessMemory(handle, uintptr(address), uintptr(unsafe.Pointer(&byteArray[0])), uintptr(len(byteArray)))
}
func writeSet(address int, byteArray []byte) {
	go func() {
		for {
			writeHelper(address, []byte{0x88, 0x13})
		}
	}()
	time.Sleep(time.Second * T)
}
func uint16ToByte(val []uint16) (fstOffset int){
	b := make([]byte, 8)
	b[0] = byte(val[3] >> 8)
	b[1] = byte(val[3])
	b[2] = byte(val[2] >> 8)
	b[3] = byte(val[2])
	b[4] = byte(val[1] >> 8)
	b[5] = byte(val[1])
	b[6] = byte(val[0] >> 8)
	b[7] = byte(val[0])
	fstOffset = int(binary.BigEndian.Uint64(b))
	return
}


func readHelper(baseOffset int, offsets []int) int {
	baseNOffset := int(info.BaseOfDll + uintptr(baseOffset))
	val, _, _ := w32.ReadProcessMemory(handle, ptr(baseNOffset), 8)
	fstsummed := 0

	for _, k := range offsets {
		fstsummed = uint16ToByte(val) + k
		val, _, _ = w32.ReadProcessMemory(handle, ptr(fstsummed), 4)
	}
	return fstsummed
}
func simpleReadWrite(baseOffset int, offsets []int, byteArray []byte) {
	address := readHelper(baseOffset, offsets)
	writeHelper(address, byteArray)
}

func main() {
	list, err := processes()
	proc := findProcessByName(list, "Tutorial-x86_64.exe")
	pid := proc.ProcessID
	PROCESS_ALL_ACCESS := syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xfff
	handle, err = w32.OpenProcess(PROCESS_ALL_ACCESS, true, ptr(pid))
	if err != nil {
		fmt.Println(err)
	}
	module, _ := EnumProcessModule(windows.Handle(handle))

	ret, _, err := getModuleInformation.Call(uintptr(handle), uintptr(module),
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))

	if ret == 0 {
		fmt.Println(err)
	}

	var level int
	for {
		fmt.Println("insert the level to solve: ")
		switch     fmt.Scan(&level); level {
		case 2:
			step2()
		case 3:
			step3()
		case 4:
			step4()
		case 5:
			step5()
		case 6:
			step6()
		case 7:
			step7()
		case 8:
			step8()
		case 9:
			step9()
		case 0:
			break
		default:
			fmt.Println("select a level from 2 to 9\n\r0 to exit")
		}
	}

}

func step2() {
	baseNOffset := int(info.BaseOfDll + 0x00306A70)
	val, _, _ := w32.ReadProcessMemory(handle, ptr(baseNOffset), 4)
	add := uint16ToByte(val)
	writeHelper(add+0x7F0,[]byte{0xe8, 3, 0, 0})
}

func step3() {
	baseNOffset := int(info.BaseOfDll + 0x00309CA0)
	val, _, _ := w32.ReadProcessMemory(handle, ptr(baseNOffset), 4)
	fstsummed := 0
	for _, k := range []int{0x58, 0x88, 0x10, 0x480, 0x20, 0x960, 0x810} {
		fstOffset := uint16ToByte(val)

		fstsummed = fstOffset + k
		val, _, _ = w32.ReadProcessMemory(handle, ptr(fstsummed), 4)
	}
	writeHelper(fstsummed,[]byte{0x88,0x13,0,0})
}

func step4() {
	simpleReadWrite(0x00306AA0, []int{0xd0, 0x28, 0xF8, 0x18, 0x80, 0x28, 0x818}, []byte{0x00, 0x40, 0x9c, 0x45})
	simpleReadWrite(0x00306AA0, []int{0xd0, 0x28, 0xF8, 0x18, 0x88, 0x28, 0x820}, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xb3, 0x40})
}

func step5() {
	writeHelper(0x10002C5B8, []byte{0x90, 0x90})
}

func step6() {
	address := readHelper(0x00306AD0, []int{0})
	writeHelper(address, []byte{0x88, 0x13, 0, 0})
}

func step7() {
	writeHelper(int(info.BaseOfDll+0x2d4f7), []byte{0x83, 0x86, 0xE0, 0x07, 0x00, 0x00, 0x02})
}
func step8() {
	address := readHelper(0x00306B00, []int{0x10, 0x18, 0x0, 0x18})
	writeSet(address, []byte{0x88, 0x13})
}

func step9() {
	ToFind := []byte{0xF3, 0x0F, 0x11, 0x43, 0x08, 0x0F}
	for i := 0; i < int(info.SizeOfImage); i++ {
		baseNOffset := int(info.BaseOfDll + uintptr(i))
		val, _, _ := w32.ReadProcessMemory(handle, ptr(baseNOffset), 6)
		b := make([]byte, 6)
		b[5] = byte(val[2] >> 8)
		b[4] = byte(val[2])
		b[3] = byte(val[1] >> 8)
		b[2] = byte(val[1])
		b[1] = byte(val[0] >> 8)
		b[0] = byte(val[0])
		res := bytes.Compare(b, ToFind)
		if res == 0 {
			fmt.Printf("found at offset %x\n\r", i)
			address := 0xFFFF0000
			w32.VirtualAllocEx(handle, uintptr(address), uintptr(2048), 0x00001000|0x00002000, 0x04)
			writeHelper(int(info.BaseOfDll+uintptr(i)), []byte{0xe9, 0x8e, 0x14, 0xfc, 0xff})
			writeHelper(address, []byte{0x83, 0x7B, 0x14, 0x01, 0x0F, 0x85, 0x0C, 0x00, 0x00, 0x00, 0xC7, 0x43, 0x08, 0x00, 0x00, 0x7A, 0x44, 0xE9, 0x5C, 0xEB, 0x03, 0x00, 0xC7, 0x43, 0x08, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x50, 0xEB, 0x03, 0x00})
			oldProtect := windows.PAGE_READWRITE
			_, _, errVirtualProtectEx := procVirtualProtect.Call(uintptr(handle), uintptr(0xFFFF0000), uintptr(2048), uintptr(syscall.PAGE_EXECUTE_READWRITE), uintptr(unsafe.Pointer(&oldProtect)))
			fmt.Println(errVirtualProtectEx)
		}
	}
}

//TODO: finish graphic level
/*
func stepg1() {
	baseNOffset := int(info.BaseOfDll + 0x003CED40)
	val, _, _ := w32.ReadProcessMemory(handle, ptr(baseNOffset), 4)
	fstsummed := 0
	for _, k := range []int{0xb70} {
		b := make([]byte, 4)
		b[0] = byte(val[1] >> 8)
		b[1] = byte(val[1])
		b[2] = byte(val[0] >> 8)
		b[3] = byte(val[0])
		fstOffset := binary.BigEndian.Uint32(b)
		fstsummed = int(fstOffset) + k
		val, _, _ = w32.ReadProcessMemory(handle, ptr(fstsummed), 4)
	}
	fmt.Println(val)
	var s []byte
	s = make([]byte, 1, 1)
	s = []byte{0x01}
	w32.WriteProcessMemory(handle, ptr(fstsummed), uintptr(unsafe.Pointer(&s[0])), 1)
}

func stepg2() {
	baseNOffset := int(info.BaseOfDll + 0x002415A0)
	val, _, _ := w32.ReadProcessMemory(handle, ptr(baseNOffset), 4)
	fstsummed := 0
	for _, k := range []int{0x258, 0xf8, 0x18, 0x3f0, 0x668, 0x18, 0xbb8} {
		b := make([]byte, 4)
		b[0] = byte(val[1] >> 8)
		b[1] = byte(val[1])
		b[2] = byte(val[0] >> 8)
		b[3] = byte(val[0])
		fstOffset := binary.BigEndian.Uint32(b)
		fstsummed = int(fstOffset) + k
		val, _, _ = w32.ReadProcessMemory(handle, ptr(fstsummed), 4)
	}
	fmt.Println(val)
	var s []byte
	s = make([]byte, 1, 1)
	s = []byte{0x01}
	w32.WriteProcessMemory(handle, ptr(fstsummed), uintptr(unsafe.Pointer(&s[0])), 1)

	baseNOffset = int(info.BaseOfDll + 0x002415b0)
	val, _, _ = w32.ReadProcessMemory(handle, ptr(baseNOffset), 4)
	fstsummed = 0
	for _, k := range []int{0x110, 0x668, 0x18, 0x9d8} {
		b := make([]byte, 4)
		b[0] = byte(val[1] >> 8)
		b[1] = byte(val[1])
		b[2] = byte(val[0] >> 8)
		b[3] = byte(val[0])
		fstOffset := binary.BigEndian.Uint32(b)
		fstsummed = int(fstOffset) + k
		val, _, _ = w32.ReadProcessMemory(handle, ptr(fstsummed), 4)
	}
	fmt.Println(val)
	w32.WriteProcessMemory(handle, ptr(fstsummed), uintptr(unsafe.Pointer(&s[0])), 1)
}


*/

func ptr(val interface{}) uintptr {
	switch val.(type) {
	case string:
		return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(val.(string))))
	case int:
		return uintptr(val.(int))
	default:
		return uintptr(0)
	}
}