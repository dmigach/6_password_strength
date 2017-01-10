import string
import os
import getpass
import argparse

TOP_SCORE = 10.0


def password_check(password):
    strength = 0
    list_of_conditions = [
        len(password) >= 8,
        len(password) >= 12,
        not password.isnumeric() and
        not password.islower() and not password.isupper(),
        any(char.isdigit() for char in password),
        any(char in string.punctuation for char in password)
        ]
    condition_coefficient = TOP_SCORE / len(list_of_conditions)
    for condition in list_of_conditions:
        strength += condition_coefficient * condition
    return round(strength, 1)


def load_blacklist(file_path):
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'r') as file_handler:
        return file_handler.read()


def check_password_in_blacklist(password, blacklist):
    if blacklist is not None:
        return password in blacklist


def get_password_to_check():
    return getpass.getpass('Type password to check\n')


def get_path_to_blacklist():
    parser = argparse.ArgumentParser(
        description='Evaluate password complexity')
    parser.add_argument("blacklist", nargs='?', type=str,
                        help="path to passwords blacklist")
    args = parser.parse_args()
    return args.blacklist if args.blacklist else ''


if __name__ == '__main__':
    password_to_check = get_password_to_check()
    if password_to_check:
        path_to_blacklist = get_path_to_blacklist()
        black_list = load_blacklist(path_to_blacklist)
        if black_list is None:
            print('Wrong blacklist path\n')
        password_strength = password_check(password_to_check)
        blacklist_check_result = check_password_in_blacklist(password_to_check,
                                                             black_list)
        password_strength *= not blacklist_check_result
        if blacklist_check_result is None:
            print('Evaluation is not complete because we could not verify '
                  'the existence of the password in black lists.\n')
        else:
            print('Your password is {}in the blacklist.\n'.format(
                'not ' * (not blacklist_check_result)))
        print('Password strength is {}/{}\n'.format(password_strength,
                                                    TOP_SCORE))
    else:
        print('Since you haven\'t typed anything, there is nothing to check.')
