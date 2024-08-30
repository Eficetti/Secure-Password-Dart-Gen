import 'package:args/args.dart';
import 'package:spg/spg.dart';

void main(List<String> arguments) {
  final parser = ArgParser()
    ..addOption('length', abbr: 'l', help: 'Password length', defaultsTo: '18')
    ..addFlag('hash', abbr: 'h', help: 'Hash the password', negatable: false)
    ..addOption('custom-chars', abbr: 'c', help: 'Custom character set')
    ..addFlag(
      'evaluate',
      abbr: 'e',
      help: 'Evaluate password strength',
      negatable: false,
    )
    ..addFlag('help', abbr: '?', help: 'Show this help', negatable: false);

  try {
    final results = parser.parse(arguments);

    if (results['help'] == true) {
      print('Usage: dart spg_cli.dart [options]');
      print(parser.usage);
      return;
    }

    final length = int.parse(results['length'] as String);
    final needHash = results['hash'];
    final customChars = results['custom-chars'];
    final evaluate = results['evaluate'];

    final password = Spg.generateRandomPassword(
      length: length,
      needHash: needHash as bool,
      customCharSet: customChars as String?,
    );

    print('Generated password: $password');

    if (evaluate == true) {
      final strength = Spg.evaluatePasswordStrength(password);
      print('Password strength: $strength');
    }
  } on FormatException catch (e) {
    print('Error: ${e.message}');
    print('Usage: dart spg_cli.dart [options]');
    print(parser.usage);
  } catch (e) {
    print('Error: $e');
  }
}
