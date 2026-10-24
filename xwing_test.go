package xwing

import (
	"fmt"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name string
		seed string
		sk   string
		pk   string
	}{
		{
			name: "KAT 1",
			seed: "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
			sk:   "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
			pk:   "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
		},
		{
			name: "KAT 2",
			seed: "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
			sk:   "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
			pk:   "0333285fa253661508c9fb444852caa4061636cb060e69943b431400134ae1fbc02287247cb38068bbb89e6714af10a3fcda6613acc4b5e4b0d6eb960c302a0253b1f507b596f0884d351da89b01c35543214c8e542390b2bc497967961ef10286879c34316e6483b644fc27e8019d73024ba1d1cc83650bb068a5431b33d1221b3d122dc1239010a55cb13782140893f30aca7c09380255a0c621602ffbb6a9db064c1406d12723ab3bbe2950a21fe521b160b30b16724cc359754b4c88342651333ea9412d5137791cf75558ebc5c54c520dd6c622a059f6b332ccebb9f24103e59a297cd69e4a48a3bfe53a5958559e840db5c023f66c10ce23081c2c8261d744799ba078285cfa71ac51f44708d0a6212c3993340724b3ac38f63e82a889a4fc581f6b8353cc6233ac8f5394b6cca292f892360570a3031c90c4da3f02a895677390e60c24684a405f69ccf1a7b95312a47c844a4f9c2c4a37696dc10072a87bf41a2717d45b2a99ce09a4898d5a3f6b67085f9a626646bcf369982d483972b9cd7d244c4f49970f766a22507925eca7df99a491d80c27723e84c7b49b633a46b46785a16a41e02c538251622117364615d9c2cdaa1687a860c18bfc9ce8690efb2a524cb97cdfd1a4ea661fa7d08817998af838679b07c9db8455e2167a67c14d6a347522e89e8971270bec858364b1c1023b82c483cf8a8b76f040fe41c24dec2d49f6376170660605b80383391c4abad1136d874a77ef73b440758b6e7059add20873192e6e372e069c22c5425188e5c240cb3a6e29197ad17e87ec41a813af68531f262a6db25bbdb8a15d2ed9c9f35b9f2063890bd26ef09426f225aa1e6008d31600a29bcdf3b10d0bc72788d35e25f4976b3ca6ac7cbf0b442ae399b225d9714d0638a864bda7018d3b7c793bd2ace6ac68f4284d10977cc029cf203c5698f15a06b162d6c8b4fd40c6af40824f9c6101bb94e9327869ab7efd835dfc805367160d6c8571e3643ac70cbad5b96a1ad99352793f5af71705f95126cb4787392e94d808491a2245064ba5a7a30c066301392a6c315336e10dbc9c2177c7af382765b6c88eeab51588d01d6a95747f3652dc5b5c401a23863c7a0343737c737c99287a40a90896d4594730b552b910d23244684206f0eb842fb9aa316ab182282a75fb72b6806cea4774b822169c386a58773c3edc8229d85905abb87ac228f0f7a2ce9a497bb5325e17a6a82777a997c036c3b862d29c14682ad325a9600872f3913029a1588648ba590a7157809ff740b5138380015c40e9fb90f0311107946f28e5962e21666ad65092a3a60480cd16e61ff7fb5b44b70cf12201878428ef8067fceb1e1dcb49d66c773d312c7e53238cb620e126187009472d41036b702032411dc96cb750631df9d99452e495deb4300df660c8d35f32b424e98c7ed14b12d8ab11a289ac63c50a24d52925950e49ba6bf4c2c38953c92d60b6cd034e575c711ac41bfa66951f62b9392828d7b45aed377ac69c35f1c6b80f388f34e0bb9ce8167eb2bc630382825c396a407e905108081b444ac8a07c2507376a750d18248ee0a81c4318d9a38fc44c3b41e8681f87c34138442659512c41276e1cc8fc4eb66e12727bcb5a9e0e405cdea21538d6ea885ab169050e6b91e1b69f7ed34bcbb48fd4c562a576549f85b528c953926d96ea8a160b8843f1c89c62",
		},
		{
			name: "KAT 3",
			seed: "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
			sk:   "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
			pk:   "36244278824f77c621c660892c1c3886a9560caa52a97c461fd3958a598e749bbc8c7798ac8870bac7318ac2b863000ca3b0bdcbbc1ccfcb1a30875df9a76976763247083e646ccb2499a4e4f0c9f4125378ba3da1999538b86f99f2328332c177d1192b849413e65510128973f679d23253850bb6c347ba7ca81b5e6ac4c574565c731740b3cd8c9756caac39fba7ac422acc60c6c1a645b94e3b6d21485ebad9c4fe5bb4ea0853670c5246652bff65ce8381cb473c40c1a0cd06b54dcec11872b351397c0eaf995bebdb6573000cbe2496600ba76c8cb023ec260f0571e3ec12a9c82d9db3c57b3a99e8701f78db4fabc1cc58b1bae02745073a81fc8045439ba3b885581a283a1ba64e103610aabb4ddfe9959e7241011b2638b56ba6a982ef610c514a57212555db9a98fb6bcf0e91660ec15dfa66a67408596e9ccb97489a09a073ffd1a0a7ebbe71aa5ff793cb91964160703b4b6c9c5390842c2c905d4a9f88111fed57874ba9b03cf611e70486edf539767c7485189d5f1b08e32a274dc24a39c918fd2a4dfa946a8c897486f2c974031b2804aabc81749db430b85311372a3b8478868200b40e043f7bf4a1c3a08b0771b431e342ee277410bca034a0c77086c8f702b3aed2b4108bbd3af471633373a1ac74b128b148d1b9412aa66948cac6dc6614681fda02ca86675d2a756003c49c50f06e13c63ce4bc9f321c860b202ee931834930011f485c9af86b9f642f0c353ad305c66996b9a136b753973929495f0d8048db75529edcb4935904797ac66605490f66329c3bb36b8573a3e00f817b3082162ff106674d11b261baae0506cde7e69fdce93c6c7b59b9d4c759758acf287c2e4c4bfab5170a9236daf21bdb6005e92464ee8863f845cf37978ef19969264a516fe992c93b5f7ae7cb6718ac69257d630379e4aac6029cb906f98d91c92d118c36a6d16115d4c8f16066078badd161a65ba51e0252bc358c67cd2c4beab2537e42956e08a39cfccf0cd875b5499ee952c83a162c68084f6d35cf92f71ec66baec74ab87e2243160b64df54afb5a07f78ec0f5c5759e5a4322bca2643425748a1a97c62108510c44fd9089c5a7c14e57b1b77532800013027cff91922d7c935b4202bb507aa47598a6a5a030117210d4c49c174700550ad6f82ad40e965598b86bc575448eb19d70380d465c1f870824c026d74a2522a799b7b122d06c83aa64c0974635897261433914fdfb14106c230425a83dc8467ad8234f086c72a47418be9cfb582b1dcfa3d9aa45299b79fff265356d8286a1ca2f3c2184b2a70d15289e5b202d03b64c735a867b1154c55533ff61d6c296277011848143bc85a4b823040ae025a29293ab77747d85310078682e0ba0ac236548d905a79494324574d417c7a3457bd5fb5253c4876679034ae844d0d05010fec722db5621e3a67a2d58e2ff33b432269169b51f9dcc095b8406dc1864cf0aeb6a2132661a38d641877594b3c51892b9364d25c63d637140a2018d10931b0daa5a2f2a405017688c991e586b522f94b1132bc7e87a63246475816c8be9c62b731691ab912eb656ce2619225663364701a014b7d0337212caa2ecc731f34438289e0ca4590a276802d980056b5d0d316cae2ecfea6d86696a9f161aa90ad47eaad8cadd31ae3cbc1c013747dfee80fb35b5299f555dcc2b787ea4f6f16ffdf66952461",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := DecodeHex(t, tt.seed)
			sk, pk, err := generateKeyPair(seed)
			if err != nil {
				t.Fatalf("generateKeyPair() error = %v", err)
			}

			wantsk := DecodeHex(t, tt.sk)
			wantpk := DecodeHex(t, tt.pk)
			AssertBytesEqual(t, sk.Bytes(), wantsk)
			AssertBytesEqual(t, pk.Bytes(), wantpk)
		})
	}
}

func TestXWing(t *testing.T) {
	const roundtrips = 10
	for i := range roundtrips {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			sk, pk, err := GenerateKeyPair()
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}

			ss, ct, err := pk.Encapsulate()
			if err != nil {
				t.Fatalf("Encapsulate() error = %v", err)
			}

			gotss, err := sk.Decapsulate(ct)
			if err != nil {
				t.Fatalf("Decapsulate() error = %v", err)
			}

			AssertBytesEqual(t, gotss, ss)
		})
	}
}

func FuzzXWing(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 64))
	f.Fuzz(func(t *testing.T, seed []byte, eseed []byte) {
		if len(seed) != 32 || len(eseed) != 64 {
			t.Skip()
		}

		sk, pk, err := generateKeyPair(seed)
		if err != nil {
			t.Fatalf("generateKeyPair() error = %v", err)
		}

		ss, ct, err := pk.encapsulate(eseed)
		if err != nil {
			t.Fatalf("encapsulate() error = %v", err)
		}

		gotss, err := sk.Decapsulate(ct)
		if err != nil {
			t.Fatalf("Decapsulate() error = %v", err)
		}

		AssertBytesEqual(t, gotss, ss)
	})
}

func enforceFIPS(t *testing.T) {
	t.Helper()
	old := fipsEnforced
	fipsEnforced = func() bool { return true }
	t.Cleanup(func() { fipsEnforced = old })
}

func TestErrUnsupported(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	_, ct, err := pk.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate() error = %v", err)
	}

	enforceFIPS(t)

	t.Run("GenerateKeyPair", func(t *testing.T) {
		sk, pk, err := GenerateKeyPair()
		AssertError(t, err, ErrUnsupported)
		if sk != nil || pk != nil {
			t.Error("GenerateKeyPair() returned non-nil keys with an error")
		}
	})

	t.Run("generateKeyPair", func(t *testing.T) {
		sk, pk, err := generateKeyPair(make([]byte, DecapsulationKeySize))
		AssertError(t, err, ErrUnsupported)
		if sk != nil || pk != nil {
			t.Error("generateKeyPair() returned non-nil keys with an error")
		}
	})

	t.Run("NewDecapsulationKey", func(t *testing.T) {
		k, err := NewDecapsulationKey(sk.Bytes())
		AssertError(t, err, ErrUnsupported)
		if k != nil {
			t.Error("NewDecapsulationKey() returned a non-nil key with an error")
		}
	})

	t.Run("NewEncapsulationKey", func(t *testing.T) {
		k, err := NewEncapsulationKey(pk.Bytes())
		AssertError(t, err, ErrUnsupported)
		if k != nil {
			t.Error("NewEncapsulationKey() returned a non-nil key with an error")
		}
	})

	t.Run("Encapsulate", func(t *testing.T) {
		ss, ct, err := pk.Encapsulate()
		AssertError(t, err, ErrUnsupported)
		if ss != nil || ct != nil {
			t.Error("Encapsulate() returned non-nil output with an error")
		}
	})

	t.Run("Decapsulate", func(t *testing.T) {
		ss, err := sk.Decapsulate(ct)
		AssertError(t, err, ErrUnsupported)
		if ss != nil {
			t.Error("Decapsulate() returned a non-nil secret with an error")
		}
	})

	t.Run("encapsulate", func(t *testing.T) {
		ss, ct, err := pk.encapsulate(make([]byte, eseedSize))
		AssertError(t, err, ErrUnsupported)
		if ss != nil || ct != nil {
			t.Error("encapsulate() returned non-nil output with an error")
		}
	})
}
