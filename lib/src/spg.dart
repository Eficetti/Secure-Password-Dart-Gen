import 'dart:math';
import 'package:spg/src/hash.dart';

/// {@template spg}
/// Secure Password Generator
/// {@endtemplate}
class Spg {
  ///
  const Spg();

  static const _lowercaseLetters = 'abcdefghijklmnopqrstuvwxyz';
  static const _uppercaseLetters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  static const _digits = '0123456789';
  static const _specialChars = r'!@#$%^&*()-_=+[]{};:,.<>?/|';

  /// Generates a secure random password.
  ///
  /// [length] is the desired length of the password (minimum 12).
  /// [needHash] indicates whether to return the hashed password.
  /// [customCharSet] allows specifying a custom character set.
  static String generateRandomPassword({
    int length = 18,
    bool needHash = false,
    String? customCharSet,
  }) {
    if (length < 12) {
      throw ArgumentError('Password length must be at least 12 characters');
    }

    final rand = Random.secure();
    final passwordChars = <String>[];

    final charSet = customCharSet ??
        _lowercaseLetters + _uppercaseLetters + _digits + _specialChars;

    // Ensure at least one character from each group if not using a custom set
    if (customCharSet == null) {
      passwordChars.add(_getRandomChar(_lowercaseLetters, rand));
      passwordChars.add(_getRandomChar(_uppercaseLetters, rand));
      passwordChars.add(_getRandomChar(_digits, rand));
      passwordChars.add(_getRandomChar(_specialChars, rand));
    }

    // Fill the rest of the password with random characters
    while (passwordChars.length < length) {
      passwordChars.add(_getRandomChar(charSet, rand));
    }

    // Shuffle the characters to ensure randomness
    passwordChars.shuffle(rand);

    final password = passwordChars.join();

    if (needHash) {
      return PasswordHashManager.hash(password);
    }

    return password;
  }

  static String _getRandomChar(String charSet, Random rand) {
    return charSet[rand.nextInt(charSet.length)];
  }

  /// Validates if a password matches its hashed version.
  static bool validatePassword({
    required String password,
    required String hashedPassword,
  }) {
    return PasswordHashManager.verify(
      password: password,
      hashedPassword: hashedPassword,
    );
  }

  /// Evaluates the strength of a password.
  static String evaluatePasswordStrength(String password) {
    var score = 0;

    if (password.length >= 12) score += 2;
    if (password.length >= 16) score += 2;
    if (RegExp(r'[a-z]').hasMatch(password)) score++;
    if (RegExp(r'[A-Z]').hasMatch(password)) score++;
    if (RegExp(r'[0-9]').hasMatch(password)) score++;
    if (RegExp(r'[!@#$%^&*()-_=+\[\]{};:,.<>?/|]').hasMatch(password)) score++;

    if (score < 3) return 'Weak';
    if (score < 5) return 'Moderate';
    if (score < 7) return 'Strong';
    return 'Very Strong';
  }
}
