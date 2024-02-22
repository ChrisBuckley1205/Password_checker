import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)

    if res.status_code !=200:
        raise RuntimeError(f'Error Fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0 # to exit loop




def pwned_api_check(password):
    #check password if it exists in api response

    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char,tail = sha1password[:5], sha1password[5:] #this says "grab beginning to 5th char, from 5th to end
    response = request_api_data(first5_char)
    print(response)

    return get_password_leaks(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times.... you should probably change your password')
        else:
            print(f'{password} was NOT found. Carry On!')

    return 'done!'

if __name__=='__main__':
    main(sys.argv[1:])
