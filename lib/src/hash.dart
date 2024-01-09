import 'package:dbcrypt/dbcrypt.dart';

///
class PasswordHashManager {
  ///
  static String hash(String password) {
    return DBCrypt().hashpw(password, DBCrypt().gensalt());
  }

  ///
  static bool verify({
    required String password,
    required String hashedPassword,
  }) {
    return DBCrypt().checkpw(password, hashedPassword);
  }
}
