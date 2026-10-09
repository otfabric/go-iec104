// SPDX-License-Identifier: MIT

// Package client implements the controlling station (master) of
// IEC 60870-5-104.
//
// A [Client] owns one connection to a controlled station. It runs the
// protocol machine (sequence numbers, acknowledgements, the t1/t2/t3
// timers and the k/w windows), delivers every received ASDU to a [Handler]
// and offers the application functions of the standard as blocking calls:
//
//	c, err := client.Dial(ctx, "10.0.0.5:2404",
//		client.WithHandler(client.HandlerFunc(func(a *asdu.ASDU) {
//			fmt.Println(a)
//		})))
//	if err != nil { ... }
//	defer c.Close()
//
//	points, err := c.Interrogate(ctx, 1, asdu.QOIStation)
//	err = c.Command(ctx, 1, asdu.SingleCommand{IOA: 6001, Value: true})
//
// All methods are safe for concurrent use.
package client
