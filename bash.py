import os
import subprocess


def verify_signature(signed_file, root_certificate, content_file):
    """
    Verifies a PKCS#7 signed file using OpenSSL.

    openssl cms -verify -in file1.p7b -inform DER -content file1.txt -CAfile client_chain.pem -out verified.txt

    Returns:
    str: The output from the OpenSSL command.
    """
    # Command to run in the shell
    command = [
        'openssl', 'cms', '-verify',
        '-in', signed_file,
        '-CAfile', root_certificate,
        '-inform', 'DER',
        '-content', content_file,
        '-out', 'verified.txt'
    ]

    # Execute the command
    try:
        result = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        textStd = result.stdout + result.stderr

        if 'Verification failed' in textStd:
            return {'message': 'Failed', 'std': textStd, 'executed': ' '.join(command), 'path': os.getcwd()}
        elif 'CMS Verification successful' in textStd:
            return {'message': 'Verified', 'std': textStd, 'executed': ' '.join(command), 'path': os.getcwd()}
        else:
            return {'message': 'Error', 'std': textStd, 'executed': ' '.join(command), 'path': os.getcwd()}

    except subprocess.CalledProcessError as e:
        return {'message': 'Failed', 'executed': ' '.join(command), 'path': os.getcwd()}


