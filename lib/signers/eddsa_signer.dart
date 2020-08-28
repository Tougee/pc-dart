
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/src/registry/registry.dart';

class EdDSASigner implements Signer {
  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG =
  DynamicFactoryConfig.suffix(Signer, '/EdDSA', (_, Match match) {
    return () => EdDSASigner();
  });


  bool _forSigning;
  EdDSAAsymmetricKey _key;

  @override
  String get algorithmName => 'EdDSA';

  @override
  void init(bool forSigning, CipherParameters params) {
    _forSigning = forSigning;

    AsymmetricKeyParameter akparams;
    if (params is ParametersWithRandom) {
      akparams = params.parameters as AsymmetricKeyParameter<AsymmetricKey>;
    } else {
      akparams = params as AsymmetricKeyParameter<AsymmetricKey>;
    }
    var k = akparams.key as EdDSAAsymmetricKey;

    if (forSigning && (k is! EdDSAPrivateKey)) {
      throw ArgumentError('Signing requires private key');
    }

    if (!forSigning && (k is! EdDSAPublicKey)) {
      throw ArgumentError('Verification requires public key');
    }

    _key = k;
  }

  @override
  EdDSASignature generateSignature(Uint8List message) {
    if (!_forSigning) {
      throw StateError('Signer was not initialised for signature generation');
    }
    var privateKey = (_key as EdDSAPrivateKey).private;
    var sig = sign(privateKey, message);
    return EdDSASignature(sig);
  }

  @override
  void reset() {}

  @override
  bool verifySignature(Uint8List message, covariant EdDSASignature signature) {
    if (_forSigning) {
      throw StateError('Signer was not initialised for signature verification');
    }
    var publicKey = (_key as EdDSAPublicKey).publicKey;
    return verify(publicKey, message, signature.bytes);
  }

}