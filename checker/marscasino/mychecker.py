#!/usr/bin/python3
from ctf_gameserver import checkerlib

import logging
import requests
import random
import string
import hashlib
import datetime
import re
import base64
import ed25519

SIGN_KEY = b'LVXETNKv0b8ecxA688T+jkpVjxAqZlVMGEB4dUALBXgPHzk+K71hifJJo8VrrLOu/LrceTOSxx68BZOTUlUzEA=='
PORT = 7777

# random length if length = 0
def random_string(l=12):
    l = random.randint(6,15) if l<=0 else l
    return "".join([random.choice(string.ascii_letters + string.digits) for _ in range(l)])

def random_name():
    t = "".join([random.choice(string.ascii_letters) for _ in range(4)])
    return t + "".join([random.choice(string.digits) for _ in range(4)])


class MarscasinoChecker(checkerlib.BaseChecker):

    def __init__(self, ip, team):
        checkerlib.BaseChecker.__init__(self, ip, team)
        self._baseurl = 'http://[%s]:%d/' % (self.ip, PORT)
        logging.info("URL: %s" % self._baseurl)
        self._current_tick = 0


    def place_flag(self, tick):
        """ Register user and place flag as his item """
        self._current_tick = tick
        reg_res = self._full_register()
        if type(reg_res) != tuple:
            # something went wrong
            return reg_res
        username, password = reg_res
        checkerlib.store_state("flag_" + str(tick), {'username': username, 'password': password})

        flag = checkerlib.get_flag(tick)
        
        s = requests.Session()
        resp = self._login(s, username, password)
        if resp.status_code != 200 or "Wrong" in resp.text:
            logging.info("Failed to login new user")
            return checkerlib.CheckResult.FAULTY
       
        resp = self._home(s, item=flag, item_cost=random.randint(4000, 8000))
        if resp.status_code != 200:
            logging.info("Failed request home")
            return checkerlib.CheckResult.FAULTY
        return checkerlib.CheckResult.OK


    def check_flag(self, tick):
        """ Login user and check for flag item """
        flag = checkerlib.get_flag(tick)
        data = checkerlib.load_state("flag_" + str(tick))
        if not data:
            return checkerlib.CheckResult.FLAG_NOT_FOUND
        logging.info("Check flag %s for tick %d" % (flag, tick))

        s = requests.Session()
        resp = self._login(s, data['username'], data['password'])
        if resp.status_code != 200 or "Wrong" in resp.text:
            return checkerlib.CheckResult.FLAG_NOT_FOUND
       
        resp = self._home(s)
        if resp.status_code != 200:
            logging.info("Failed to request home")
            return checkerlib.CheckResult.FAULTY
        
        if flag in resp.text:
            return checkerlib.CheckResult.OK
        else:
            return checkerlib.CheckResult.FLAG_NOT_FOUND


    def check_service(self):
        """ Test various actions the user can do.
            After X ticks, the checker buys expensive items """

        users = checkerlib.load_state("users")
        reg_res = self._full_register()
        if type(reg_res) != tuple:
            # something went wrong
            return reg_res
        user = {'username': reg_res[0], 'password': reg_res[1]}
        if users:
            users.append(user)
        else:
            users = [user]
        checkerlib.store_state("users", users)

        # do all checks
        res = self._check_voucher(user)
        if res is not checkerlib.CheckResult.OK:
            return res

        if len(users) > 1:
            res = self._check_friendcode(user)
            if res is not checkerlib.CheckResult.OK:
                return res

        logging.info("Enter loop")
        cnt = 0
        while len(users) > 1 and cnt < 5:
            res = self._check_buy_item(user)
            if not res:
                cnt += 1
                continue
            if res is not checkerlib.CheckResult.OK:
                return res
            if res is checkerlib.CheckResult.OK:
                break

        logging.info("End loop")

        return checkerlib.CheckResult.OK


    def _check_buy_exp_item(self):
        """ Check if user can buy expensive item """
        s1 = requests.Session()
        s2 = requests.Session()

        # register new user
        reg_res = self._full_register(fcode='', name=False)
        if type(reg_res) != tuple:
            # something went wrong
            return reg_res
        resp = self._login(s1, reg_res[0], reg_res[1])
        if resp.status_code != 200 or "Wrong" in resp.text:
            logging.info("Failed to login the new user")
            return checkerlib.CheckResult.FAULTY

        # Give user some money
        sk = ed25519.SigningKey(base64.b64decode(SIGN_KEY))
        payload = "%s;%s;%s" % (reg_res[0], 10000, self.ip)
        sig = sk.sign(payload.encode(), encoding="base64").decode()
        resp = requests.get(self._baseurl + "donation?p=%s&s=%s" % (payload, sig))
        if resp.status_code != 200 or "ok" not in resp.text:
            logging.info("Failed donation")
            return checkerlib.CheckResult.FAULTY

        # Select random expensive seller
        sellers = checkerlib.load_state("sellers")
        prv_seller = sellers[-2] 
        cur_seller = None
        random.shuffle(sellers)

        # Buy something
        buy_success = False
        for u in sellers[:5]:
            resp = self._buy(s1, u['username'])
            logging.info("Check buy for %s" % u['username'])
            if resp.status_code == 200 and "You bought something" in resp.text:
                logging.info("Buy worked")
                cur_seller = u
                break

        # try prv tick seller, if other sellser dont work
        if not cur_seller:
            cur_seller = prv_seller
            logging.info("Take prv seller")
            resp = self._buy(s1, prv_seller['username'])
            if resp.status_code != 200 or "You bought something" not in resp.text:
                logging.info("Failed buy from prv tick seller")
                return checkerlib.CheckResult.FAULTY

        # Login as seller to buy a flag
        resp = self._login(s2, cur_seller['username'], cur_seller['password'])
        if resp.status_code != 200 or "Wrong" in resp.text:
            logging.info("Failed login seller")
            return checkerlib.CheckResult.FAULTY
        
        flag = checkerlib.get_flag(self._current_tick - 1)
        data = checkerlib.load_state("flag_" + str(self._current_tick - 1))
        # not the users fault
        if not data:
            return checkerlib.CheckResult.OK
        resp = self._buy(s2, data['username'])
        if resp.status_code != 200 or flag not in resp.text:
            if "enough" in resp.text:
                logging.info("Fail is bcs not enough money")
            coins = re.findall(r'have (\d*) coins', resp.text)
            if len(coins) > 0:
                logging.info("Current coins: %d" % int(coins[0]))
            logging.info("Failed buy from flag")
            return checkerlib.CheckResult.FAULTY
        return checkerlib.CheckResult.OK

    def _check_voucher(self, user):
        logging.info("Check voucher")
        s = requests.Session()
        resp = self._login(s, user['username'], user['password'])
        if resp.status_code != 200 or "Wrong" in resp.text:
            logging.info("Login failed")
            return checkerlib.CheckResult.FAULTY
        resp = self._home(s, item=random_string(4), item_cost=random.randint(1, 10))
        if resp.status_code != 200:
            logging.info("Home failed")
            return checkerlib.CheckResult.FAULTY

        resp = self._get_voucher(s, 3)
        if resp.status_code != 200:
            logging.info("Get voucher failed")
            return checkerlib.CheckResult.FAULTY
        code = re.findall(r'Voucher: <b>(.*?)<', resp.text)
        if not code:
            logging.info("Failed to parse voucher")
            return checkerlib.CheckResult.FAULTY
        resp = self._activate_voucher(s, code[0])
        if resp.status_code != 200 or "You won" not in resp.text:
            logging.info("Activate voucher failed")
            return checkerlib.CheckResult.FAULTY
        return checkerlib.CheckResult.OK

    def _check_friendcode(self, user):
        logging.info("Check friend code")
        s1 = requests.Session()
        s2 = requests.Session()

        # login and get coin count + friendcode
        resp = self._login(s1, user['username'], user['password'])
        if resp.status_code != 200 or "Wrong" in resp.text:
            logging.info("Failed to login user")
            return checkerlib.CheckResult.FAULTY
        coins_old = re.findall(r'have (\d*) coins', resp.text)
        if not coins_old:
            logging.info("Failed to parse coins")
            return checkerlib.CheckResult.FAULTY
        resp = self._friend_code(s1)
        fcode = re.findall(r'>(.{32})<', resp.text)
        if not fcode:
            logging.info("Failed to get friend code")
            return checkerlib.CheckResult.FAULTY

        # register user with friendcode
        reg_res = self._full_register(fcode=fcode, name=True)
        if type(reg_res) != tuple:
            # something went wrong
            return reg_res

        # for later use
        sellers = checkerlib.load_state("sellers")
        user_sellers = {'username': reg_res[0], 'password': reg_res[1]}
        if sellers:
            sellers.append(user_sellers)
        else:
            sellers = [user_sellers]
        checkerlib.store_state("sellers", sellers)

        resp = self._login(s2, user_sellers['username'], user_sellers['password'])
        if resp.status_code != 200 or "Wrong" in resp.text:
            logging.info("Failed to login user seller")
            return checkerlib.CheckResult.FAULTY
        resp = self._home(s2, item=random_string(0), item_cost=random.randint(8000, 10000))
        if resp.status_code != 200:
            logging.info("Failed to request home")
            return checkerlib.CheckResult.FAULTY

        # compare old and new coins
        coins = re.findall(r'have (\d*) coins', resp.text)
        resp = self._home(s1)
        if resp.status_code != 200:
            logging.info("No coins in response")
            return checkerlib.CheckResult.FAULTY
        coins_new = re.findall(r'have (\d*) coins', resp.text)
        if not coins or not coins_new:
            logging.info("Failed to parse coins")
            return checkerlib.CheckResult.FAULTY
        logging.info("Old: %s; New: %s; Reg: %s" % (coins_old[0], coins_new[0], coins[0]))
        if int(coins[0]) != 50 or int(coins_old[0]) + 50 != int(coins_new[0]):
            logging.info("Friendcode was not applied")
            return checkerlib.CheckResult.FAULTY
        return checkerlib.CheckResult.OK

    def _check_buy_item(self, user):
        """ Get a random old user and buy an item """
        logging.info("Check buy item")
        s = requests.Session()
        users = checkerlib.load_state("users")
        user_test = users[:-1][random.randint(0, len(users)-2)]

        resp = self._login(s, user_test['username'], user_test['password'])

        # if it doesn't work, mby database was deleted
        # delete user and try user from prv tick
        if resp.status_code != 200 or "Wrong" in resp.text:
            logging.info("Selected user does not exist, try prv user")
            idx = [u['username'] for u in users].index(user_test['username'])
            users.remove(users[idx])
            user_test = users[-2]
            resp = self._login(s, user_test['username'], user_test['password'])
            if resp.status_code != 200 or "Wrong" in resp.text:
                logging.info("Failed to login user_test")
                return checkerlib.CheckResult.FAULTY

        # check whether the user has enough coins
        coins = re.findall(r'have (\d*) coins', resp.text)
        if not coins:
            logging.info("No coins in response")
            return checkerlib.CheckResult.FAULTY
        if int(coins[0]) < 10:
            return None

        # check if buying works
        resp = self._buy(s, user['username'])
        if resp.status_code != 200 or "You bought something" not in resp.text:
            logging.info("Item does not appear")
            return checkerlib.CheckResult.FAULTY
        return checkerlib.CheckResult.OK

    def _full_register(self, fcode='', name=True):
        # Run 3 times as the user may already exist
        s = requests.Session()
        for _ in range(3):
            if name:
                username = random_name()
                password = random_string()
            else:
                username = random_string(0)
                password = random_string(0)

            resp = self._register(s, username, password, fcode=fcode)
            if resp.status_code != 200:
                continue

            activate = re.findall(r'.{8}-.{4}-.{4}-.{4}-.{12}', resp.text)
            if len(activate) == 0:
                continue
            
            resp = self._verify(s, activate[0])
            if resp.status_code != 200:
                continue
            return username, password
        return checkerlib.CheckResult.FAULTY

    def _register(self, s, name, password, fcode=''):
        logging.info("Register %s" % name)
        ip = ":".join(["".join([random.choice(string.hexdigits) for j in range(4)]) for i in range(8)])
        data = {'username': name,'password': password,'ip': ip,'fcode': fcode}
        resp = requests.post(self._baseurl + 'register', data=data)
        return resp

    def _login(self, s, name, password):
        logging.info("Login as %s" % (name))
        data = {'username': name,'password': password}
        resp = s.post(self._baseurl + "login", data=data)
        return resp

    def _home(self, s, item=None, item_cost=None):
        if item:
            data = {'item': item,'item_cost': item_cost}
            resp = s.post(self._baseurl + "home", data=data)
        else:
            resp = s.get(self._baseurl + 'home')
        return resp

    def _verify(self, s, code): 
        resp = requests.get(self._baseurl + "verify?code=%s" % code)
        return resp

    def _buy(self, s, user): 
        resp = s.get(self._baseurl + "buy?u=%s" % user)
        return resp

    def _friend_code(self, s):
        resp = s.get(self._baseurl + 'recruite')
        return resp

    def _delete_account(self, s, name, password):
        data = {'username': name,'password': password}
        resp = s.post(self._baseurl + 'delete-account', data=data)
        return resp

    def _get_voucher(self, s, bet):
        data = {'bet': bet}
        resp = s.post(self._baseurl + 'game2', data=data)
        return resp

    def _activate_voucher(self, s, voucher):
        data = {'voucher': voucher}
        resp = s.post(self._baseurl + 'voucher', data=data)
        return resp


if __name__ == '__main__':
    checkerlib.run_check(MarscasinoChecker)
