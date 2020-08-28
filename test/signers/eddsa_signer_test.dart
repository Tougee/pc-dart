
import 'dart:convert';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/signers/eddsa_signer.dart';
import 'package:test/test.dart';

void main() {

  test('testSignVerify', () {
    var keyPair = generateKey();
    var pubk = EdDSAPublicKey(keyPair.publicKey);
    var privk = EdDSAPrivateKey(keyPair.privateKey);
    var bytesToSign = Uint8List.fromList(utf8.encode('test message'));

    final signature = edDSASign(privk, bytesToSign);
    var result = edDSAVerify(pubk, bytesToSign, signature);
    assert(result == true);

    var wrongMessage = Uint8List.fromList(utf8.encode('wrong message'));
    var wrongResult = edDSAVerify(pubk, wrongMessage, signature);
    assert(wrongResult == false);
  });
}

Uint8List edDSASign(EdDSAPrivateKey privateKey, Uint8List dataToSign) {
  final signer = EdDSASigner();
  signer.init(true, PrivateKeyParameter<EdDSAPrivateKey>(privateKey));
  final sig = signer.generateSignature(dataToSign);
  return sig.bytes;
}

bool edDSAVerify(
    EdDSAPublicKey publicKey, Uint8List signedData, Uint8List signature) {
  final sig = EdDSASignature(signature);
  final verifier = EdDSASigner();
  verifier.init(false, PublicKeyParameter<EdDSAPublicKey>(publicKey));
  return verifier.verifySignature(signedData, sig);
}