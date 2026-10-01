package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// readPassword prompts on the terminal with echo off. Without a terminal it
// reads one line from stdin, which is how scripts and tests supply it.
func readPassword(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return nil, err
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	fd := tty.Fd()
	var old syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlGetTermios, uintptr(unsafe.Pointer(&old))); e != 0 {
		return nil, e
	}
	noEcho := old
	noEcho.Lflag &^= syscall.ECHO
	noEcho.Lflag |= syscall.ICANON | syscall.ISIG
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlSetTermios, uintptr(unsafe.Pointer(&noEcho))); e != 0 {
		return nil, e
	}
	defer func() {
		syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlSetTermios, uintptr(unsafe.Pointer(&old)))
		fmt.Fprintln(tty)
	}()
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	pw := []byte(strings.TrimRight(line, "\r\n"))
	if len(pw) == 0 {
		return nil, errors.New("empty password")
	}
	return pw, nil
}

// confirm asks a yes/no question on the terminal (default no).
func confirm(prompt string) bool {
	in := os.Stdin
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		fmt.Fprint(tty, prompt+" [y/N] ")
		in = tty
	} else {
		fmt.Print(prompt + " [y/N] ")
	}
	line, _ := bufio.NewReader(in).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes" || a == "是" || a == "好"
}
