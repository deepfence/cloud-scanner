package output

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog/log"
)

type OutputFile struct {
	fileName   string
	fileHandle *os.File
	inputChan  chan *bytes.Buffer
	ctx        context.Context
	wg         *sync.WaitGroup
}

func NewOutputFile(fileName string) (*OutputFile, error) {
	obj := OutputFile{}
	obj.fileName = fileName

	if err := os.MkdirAll(filepath.Dir(fileName), 0755); err != nil {
		return nil, fmt.Errorf("os.MkdirAll: %s", err.Error())
	}

	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("os.OpenFile: %w", err.Error())
	}

	obj.fileHandle = f
	obj.inputChan = make(chan *bytes.Buffer, 200)
	obj.wg = &sync.WaitGroup{}
	obj.wg.Add(1)
	go obj.dataConsumer()
	return &obj, nil
}

func (of *OutputFile) WriteData(buff *bytes.Buffer) {
	of.inputChan <- buff
}

func (of *OutputFile) dataConsumer() {
	log.Info().Msgf("Starting file writer, filename:%s", of.fileName)
	defer func() {
		log.Info().Msgf("Finishing file writer, filename:%s", of.fileName)
		of.wg.Done()
	}()

	runFlag := true
	var err error
	for runFlag {
		select {
		case data, ok := <-of.inputChan:
			if !ok {
				runFlag = false
				break
			}
			_, err = of.fileHandle.Write(data.Bytes())
			if err != nil {
				log.Info().Msgf("Error in file write, filename: %s, error:%s",
					of.fileName, err.Error())
			}
		}
	}
}

func (of *OutputFile) CloseOutputFile() error {
	close(of.inputChan)
	of.wg.Wait()
	log.Info().Msgf("Closing the output file, filename:%s", of.fileName)
	if of.fileHandle != nil {
		return of.fileHandle.Close()
	}
	return nil
}
