package main

import (
	"Blocker/crypto"
	"fmt"
)

func main() {
	var msg string

	fmt.Print("请输入需要签名的内容：\n")
	_, err := fmt.Scanf("%s", &msg)
	if err != nil {
		return
	}
	msgSlice := []byte(msg)

	privKey := crypto.GeneratePrivateKey()
	pubKey := privKey.Public()

	//Sign
	signature := privKey.Sign(msgSlice)

	var testMsg string
	fmt.Print("请输入需要验证的内容：\n")
	_, err = fmt.Scanf("%s", &testMsg)
	if err != nil {
		return
	}

	for {
		testMsgSlice := []byte(testMsg)
		if signature.Verify(pubKey, testMsgSlice) {
			fmt.Printf("验证成功")
			break
		} else {
			fmt.Println("验证失败,请重新检查输入的值")
			fmt.Print("请输入需要验证的内容：\n")
			_, err = fmt.Scanf("%s", &testMsg)
			if err != nil {
				return
			}
		}
	}
}
