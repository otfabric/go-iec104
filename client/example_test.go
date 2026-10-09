// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	iec104 "github.com/otfabric/go-iec104"
	"github.com/otfabric/go-iec104/asdu"
	"github.com/otfabric/go-iec104/client"
)

func Example() {
	ctx := context.Background()
	c, err := client.Dial(ctx, "10.0.0.5:2404",
		client.WithReconnect(client.Reconnect{}),
		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
			fmt.Println(a) // everything the station sends, in order
		})))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	data, err := c.Interrogate(ctx, 1, asdu.QOIStation)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d ASDUs\n", len(data))
}

func ExampleClient_Command() {
	ctx := context.Background()
	c, err := client.Dial(ctx, "10.0.0.5:2404")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	// Select, then execute, a time-tagged double command.
	cmd := asdu.DoubleCommand{IOA: 6010, Value: asdu.DoubleOn, Select: true, Time: asdu.At(time.Now())}
	err = c.Command(ctx, 1, cmd)
	if err == nil {
		cmd.Select = false
		cmd.Time = asdu.At(time.Now())
		err = c.Command(ctx, 1, cmd)
	}

	var neg *iec104.NegativeError
	switch {
	case err == nil:
		fmt.Println("executed")
	case errors.As(err, &neg):
		fmt.Println("refused by the station:", neg.Cause())
	default:
		fmt.Println("failed:", err)
	}
}

func ExampleWithStateHandler() {
	c, err := client.New("10.0.0.5:2404",
		client.WithReconnect(client.Reconnect{MinDelay: time.Second, MaxDelay: time.Minute}),
		client.WithStateHandler(func(s iec104.State, err error) {
			if err != nil {
				log.Printf("connection %s: %v", s, err)
				return
			}
			log.Printf("connection %s", s)
		}))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Connect(context.Background()); err != nil {
		log.Fatal(err)
	}
}
