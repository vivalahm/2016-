from winappdbg import *

import random
import sys
import threading
import os
import shutil
import time
import optparse

SEED_DIR = os.getcwd() + os.sep + "seeds" + os.sep
CRASH_DIR = os.getcwd() + os.sep + "crashs" + os.sep


class Fuzzer:
    def __init__(self, exe_path, timeout=3, name='test', seed_dir=SEED_DIR, crash_dir=CRASH_DIR):
        self.exe_path = exe_path
        self.seed_dir = seed_dir
        self.crash_dir = crash_dir

        self.target_file = None
        self.target_name = name

        self.dbg = None
        self.kill_dbg = False
        self.pid = None
        self.in_accessv_handler = False

        self.running = False
        self.timeout = timeout
        self.iteration = 0

        self.test_cases = ["%s%n%s%n%s%n", "\xff", "\x00", "A"]

    def file_picker(self):
        file_list = os.listdir(self.seed_dir)
        o_file = random.choice(file_list)
        t_file = os.getcwd() + os.sep + self.target_name + o_file[-4:]
        shutil.copy(self.seed_dir + o_file, t_file)

        return t_file

    def fuzz(self):
        while 1:
            if not self.running:
                # We first snag a file for mutation
                self.target_file = self.file_picker()
                self.mutate_file(self.target_file)

                # Start up the debugger thread
                pydbg_thread = threading.Thread(target=self.start_debugger)
                pydbg_thread.setDaemon(0)
                pydbg_thread.start()

                while self.pid is None:
                    time.sleep(1)

                # Start up the monitoring thread
                monitor_thread = threading.Thread(target=self.monitor_debugger)
                monitor_thread.setDaemon(0)
                monitor_thread.start()

                self.iteration += 1
            else:
                time.sleep(1)

    def start_debugger(self):
        print "[*] Starting debugger for iteration: %d" % self.iteration
        self.running = True
        self.kill_dbg = False
        self.dbg = Debug(bKillOnExit=True)
        self.dbg.set_event_handler(self.crash_handler)

        try:
            self.dbg.execl('"%s" "%s"' % (self.exe_path, self.target_file))
            self.dbg.loop()

            if self.kill_dbg:
                self.dbg.stop()

        except:
            self.dbg.stop()

        finally:
            self.dbg.stop()

    def monitor_debugger(self):
        counter = 0
        print "[*] Monitor thread for pid: %d waiting." % self.pid,
        while counter < self.timeout:
            if self.in_accessv_handler:
                break
            time.sleep(1)
            print counter,
            counter += 1
        print

        if self.in_accessv_handler is not True:
            time.sleep(1)
            self.kill_dbg = True
            self.pid = None
            self.running = False
        else:
            print "[*] The access violation handler is doing its business. Going to sleep"

            while self.running:
                time.sleep(1)

    def crash_handler(self, event):
        self.pid = event.get_pid()
        code = event.get_event_code()

        if code == win32.EXCEPTION_DEBUG_EVENT and event.is_last_chance():
            time.sleep(1)
            print "[*] Crash detected, storing crash dump..."
            self.in_accessv_handler = True

            name = event.get_exception_description()
            pc = event.get_thread().get_pc()
            address = event.get_exception_address()

            crash = Crash(event)
            crash.fetch_extra_data(event, takeMemorySnapshot=0)  # no memory dump
            # crash.fetch_extra_data(event, takeMemorySnapshot=1)  # small memory dump
            # crash.fetch_extra_data(event, takeMemorySnapshot=2)  # full memory dump
            print crash.fullReport()

            '''
            # Write out the crash informations
            crash_fd = open("crashes\\crash-%d" % self.iteration, "w")
            crash_fd.write(self.crash)

            # Now backup the files
            shutil.copy("test.%s" % self.ext, "crashes\\%d.%s" % (self.iteration, self.ext))
            shutil.copy("examples\\%s" % self.test_file, "crashes\\%d_orig.%s" % (self.iteration, self.ext))
            '''
            self.in_accessv_handler = False
            self.running = False
            event.get_process().kill()

    def mutate_file(self, file):

        # Pull the contents of the file into a buffer
        fd = open(file, "rb")
        stream = fd.read()
        fd.close()

        # The fuzzing meat and potatoes, really simple
        # take a random test case and apply it to a random position
        # in the file
        test_case = random.choice(self.test_cases)

        stream_length = len(stream)
        rand_offset = random.randint(0, stream_length - 1)
        rand_len = random.randint(1, 1000)

        # Now take the test case and repeat it
        test_case = test_case * rand_len

        # Apply it to the buffer, we are just
        # splicing in our fuzz data
        fuzz_file = stream[0:rand_offset]
        fuzz_file += str(test_case)
        fuzz_file += stream[rand_offset:]

        # Write out the file
        fd = open(file, "wb")
        fd.write(fuzz_file)
        fd.close()

        return


if __name__ == "__main__":
    # This is the path to the document parser
    # and the filename extension to use
    parser = optparse.OptionParser(usage="usage: %prog [option] parameter", version="%prog 0.1v")
    parser.add_option("-x", "--exe", dest="exe_path", help="application path")
    parser.add_option("-t", "--timeout", dest="timeout", help="timeout of detect crash\tdefault: 3")
    parser.add_option("-s", "--seed", dest="seed", help="seed dir path\tdefault: ./seeds")
    parser.add_option("-c", "--crash", dest="crash", help="crash dir path\tdefault: ./crashs")
    parser.add_option("-n", "--name", dest="name", help="mutate file name\tdefault: test")

    (opt, args) = parser.parse_args()

    if not opt.exe_path:
        parser.error("exe_path is required")

    option = {k: v for k, v in opt.__dict__.items() if v is not None}
    fuzzer = Fuzzer(option)
    fuzzer.fuzz()
