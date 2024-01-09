import 'dart:math';

import 'package:spg/src/hash.dart';

/// {@template spg}
/// Secure Password Gen
/// {@endtemplate}
class Spg {
  ///
  const Spg();

  static const _lowercaseLetters = 'abcdefghijklmnopqrstuvwxyz';
  static const _uppercaseLetters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  static const _digits = '0123456789';
  static const _specialChars = r'!@#$%^&*()-_=+[]{};:,.<>?/|';

  ///
  static String generateRandomPassword({
    int length = 18,
    bool needHash = false,
  }) {
    if (length < 8) {
      throw ArgumentError('Password length should be at least 8 characters');
    }

    final rand = Random.secure();
    final passwordChars = List<String>.filled(length, '');

    // Ensure at least one character from each group
    passwordChars[0] = _getRandomChar(_lowercaseLetters, rand);
    passwordChars[1] = _getRandomChar(_uppercaseLetters, rand);
    passwordChars[2] = _getRandomChar(_digits, rand);
    passwordChars[3] = _getRandomChar(_specialChars, rand);

    // Fill the rest of the password with random characters from all groups
    const allChars =
        _lowercaseLetters + _uppercaseLetters + _digits + _specialChars;

    for (var i = 4; i < length; i++) {
      passwordChars[i] = _getRandomChar(allChars, rand);
    }

    // Shuffle the characters to ensure randomness
    passwordChars.shuffle(rand);

    if (needHash) {
      return PasswordHashManager.hash(passwordChars.join());
    }

    return passwordChars.join();
  }

  static String _getRandomChar(String charSet, Random rand) {
    return charSet[rand.nextInt(charSet.length)];
  }

  ///
  static bool validatePasswords({
    required String password,
    required String hashedPassword,
  }) {
    return PasswordHashManager.verify(
      password: password,
      hashedPassword: hashedPassword,
    );
  }
}
