# sodium
A wrapper for [libsodium](https://github.com/jedisct1/libsodium) in golang

See documents [![GoDoc](https://godoc.org/github.com/jamesruan/sodium?status.svg)](https://godoc.org/github.com/jamesruan/sodium).

Currently this is build against libsodium 1.0.12.

Following functions included:
 - `crypto_auth` `crypto_auth_verify`
 - `crypto_sign_keypair` `crypto_sign_seed_keypair` `crypto_sign_ed25519_sk_to_seed` `crypto_sign_ed25519_sk_to_pk`
 - `crypto_sign` `crypto_sign_open` `crypto_sign_detached` `crypto_sign_verify_detached`
 - `crypto_sign_init` `crypto_sign_update` `crypto_sign_final_create` `crypto_sign_final_verify`
 - `crypto_sign_ed25519_sk_to_curve25519` `crypto_sign_ed25519_pk_to_curve25519`
 - `crypto_scalarmult_base` `crypto_scalarmult`
 - `crypto_box_keypair` `crypto_box_seed_keypair`
 - `crypto_box_seal` `crypto_box_seal_open`
 - `crypto_box_easy` `crypto_box_open_easy` `crypto_box_detached` `crypto_box_open_detached`
 - `crypto_secretbox_easy` `crypto_secretbox_open_easy` `crypto_secretbox_detached` `crypto_secretbox_open_detached`
 - `crypto_pwhash` `crypto_pwhash_str` `crypto_pwhash_str_verify`
 - `crypto_pwhash_opslimit_interactive` `crypto_pwhash_memlimit_interactive`
 - `crypto_pwhash_opslimit_moderate` `crypto_pwhash_memlimit_moderate`
 - `crypto_pwhash_opslimit_sensitive` `crypto_pwhash_memlimit_sensitive`
 - `crypto_shorthash` `crypto_generichash_init` `crypto_generichash_update` `crypto_generichash_final`
 - `crypto_kdf_keygen` `crypto_kdf_derive_from_key`
 - `crypto_kx_keypair` `crypto_kx_seed_keypair` `crypto_kx_server_session_keys` `crypto_kx_client_session_keys`
 - `crypto_aead_chacha20poly1305_ietf_encrypt` `crypto_aead_chacha20poly1305_ietf_decrypt` `crypto_aead_chacha20poly1305_ietf_encrypt_detached` `crypto_aead_chacha20poly1305_ietf_decrypt_detached`
 - `sodium_memzero` `sodium_memcmp` `sodium_increment`

> NOTE: This is a modified and enhanced version based on [github.com/GoKillers/libsodium-go](https://github.com/GoKillers/libsodium-go).
> Because there're a lot of package reformat and interface changes, I'd like to launch a new project.
> Thankfully, the original author permits reuse its code as long as the original LICENSE remains.
> You can find the LICENSE.original and README.original.md stating the original license.
> And this version is released under MIT License.

