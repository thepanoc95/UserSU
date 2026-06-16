import 'dart:io';
import 'package:test/test.dart';
import 'package:usersu_dart/su_client.dart';

void main() {
  group('SuClient', () {
    final client = SuClient();

    test('--startkernel returns non-zero on non-Android', () {
      expect(client.run(['--startkernel']), isNot(0));
    });

    test('-k returns non-zero on non-Android', () {
      expect(client.run(['-k']), isNot(0));
    });

    test('-c throws ProcessException on non-Android (no /system/bin/sh)', () {
      expect(() => client.run(['-c', 'whoami']), throwsA(isA<ProcessException>()));
    });

    test('default (no args) throws ProcessException on non-Android', () {
      expect(() => client.run([]), throwsA(isA<ProcessException>()));
    });
  });
}
