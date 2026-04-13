package main

import (
	"context"
	"fmt"
	"log"

	authzx "github.com/authzx/authzx-go"
)

func main() {
	client := authzx.NewClient("azx_your_api_key_here")

	ctx := context.Background()

	allowed, err := client.Check(ctx,
		authzx.Subject{ID: "user-123"},
		"read",
		authzx.Resource{ID: "doc-456"},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Allowed:", allowed)

	resp, err := client.Authorize(ctx, &authzx.AuthorizeRequest{
		Subject:  authzx.Subject{ID: "user-123"},
		Resource: authzx.Resource{ID: "doc-456"},
		Action:   "read",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Allowed=%v Reason=%q Path=%s\n", resp.Allowed, resp.Reason, resp.AccessPath)
}
