#!/usr/bin/env python3

"""
Honeybee Project Unit Tester

---
Author: Allison Husain <$first.$last@berkeley.edu>
Date: December 31st, 2020
"""
import subprocess

TESTS_ROOT = "../honeybee_unittest_data/"
HONEY_HIVE_GENERATOR_PATH = "cmake-build-debug/honey_hive_generator"
HONEY_TESTER_PATH = "cmake-build-debug/honey_tester"
HIVE_TEMP_PATH = "/tmp/test_hive.hive"

class Test:
	__slots__ = ["display_name", "binary_path", "traces", "hive_exit_code"]
	def __init__(self, display_name, binary_path, traces):
		self.display_name = display_name
		self.binary_path = binary_path
		self.traces = traces
		
		self.hive_exit_code = -1
	
	def print_test_result_and_return_summary(self):
		"""
		Prints the results of this test and all of its traces
		"""
		overall_success = self.hive_exit_code == 0
		print(f"[[{self.display_name}]]\n* Hive generator exit code = {str(self.hive_exit_code)}")
		
		for trace in self.traces:
			description, success = trace.get_result_description_and_success()
			if not success:
				overall_success = False
			print(description)
		summary_label = "PASSED" if overall_success else "FAILED"
		print(f"* TEST {summary_label}\n")
		return overall_success
	
class Trace:
	__slots__ = ["display_name", "trace_path", "sideband_load_address", "sideband_offset", "libipt_audit_exit_code"]
	def __init__(self, display_name, trace_path, sideband_load_address, sideband_offset):
		self.display_name = display_name
		self.trace_path = trace_path
		self.sideband_load_address = sideband_load_address
		self.sideband_offset = sideband_offset
		self.libipt_audit_exit_code = -1
	
	def get_result_description_and_success(self):
		"""
		Returns a string representation of the test report. Returns true iff all modules passed on this trace.
		"""
		success = self.libipt_audit_exit_code == 0
		summary_label = "PASSED" if success else "FAILED"
		description = f"\t[[{self.display_name}]]\n"\
					  f"\t* libipt audit exit code = {str(self.libipt_audit_exit_code)}\n"\
					  f"\t* TRACE {summary_label}"
		
		return description, success
		

def generate_test_hive(test):
	"""
	Generates the hive for the test target. 
	Returns true on success.
	"""
	print(f"[***] Running hive generator on {test.display_name}")
	task = subprocess.Popen([HONEY_HIVE_GENERATOR_PATH, test.binary_path, HIVE_TEMP_PATH])
	task.communicate() #wait
	test.hive_exit_code = task.returncode
	if task.returncode != 0:
		print(f"Hive generator for {test.display_name} failed with code {str(task.returncode)}")
		return False
	return True
	
def perform_libipt_audit(test, trace):
	"""
	Performs a libipt audit to verify that the decoder and hive are working correctly.
	Requires that the analyze target has been built.
	Returns true on success.
	"""
	print(f"[***] Running libipt audit on {test.display_name}.{trace.display_name}")
	task = subprocess.Popen([HONEY_TESTER_PATH, "-a", "-h", HIVE_TEMP_PATH, "-s", trace.sideband_load_address, "-o", trace.sideband_offset, "-t", trace.trace_path, "-b", test.binary_path])
	task.communicate() #wait
	trace.libipt_audit_exit_code = task.returncode
	if task.returncode != 0:
		print(f"[!!!] {test.display_name}.{trace.display_name} failed libipt audit with code {str(task.returncode)}")
		return False
	return True


# These are the actual tests being run

tests = [
	Test("contrived_small", TESTS_ROOT + "contrived_small/small", [
		Trace("trace_1", TESTS_ROOT + "contrived_small/trace_1.pt", "0x401000", "0x1000"),
		Trace("trace_2_part_1", TESTS_ROOT + "contrived_small/trace_2_1.pt", "0x401000", "0x1000"),
		Trace("trace_2_part_2", TESTS_ROOT + "contrived_small/trace_2_2.pt", "0x401000", "0x1000"),
		Trace("trace_2_part_3", TESTS_ROOT + "contrived_small/trace_2_3.pt", "0x401000", "0x1000"),
	]),
	Test("contrived_medium", TESTS_ROOT + "contrived_medium/medium", [
		Trace("trace_1", TESTS_ROOT + "contrived_medium/trace_1.pt", "0x401000", "0x1000"),
		Trace("trace_2_part_1", TESTS_ROOT + "contrived_medium/trace_2_1.pt", "0x401000", "0x1000"),
		Trace("trace_2_part_2", TESTS_ROOT + "contrived_medium/trace_2_2.pt", "0x401000", "0x1000"),
		Trace("trace_2_part_3", TESTS_ROOT + "contrived_medium/trace_2_3.pt", "0x401000", "0x1000"),
		Trace("trace_2_part_4", TESTS_ROOT + "contrived_medium/trace_2_4.pt", "0x401000", "0x1000"),

	]),
	Test("tar", TESTS_ROOT + "tar/tar", [
		Trace("decompress_clion", TESTS_ROOT + "tar/decompress_clion.pt", "0x55555555d000", "0x9000"),
		Trace("help_page", TESTS_ROOT + "tar/help_page.pt", "0x55555555d000", "0x9000")
	]),
	Test("html_fast_parse", TESTS_ROOT + "html_fast_parse/fuzz_target", [
		Trace("6.txt", TESTS_ROOT + "html_fast_parse/6_txt.pt", "0x555555558000", "0x4000"),
	]),

# These tests not used due to slight differences in when an OVF packet is handled. This does not effect decoding in a serious way since Intel's Software Developer Manual is very vague about what should be done about OVFs since so much can be lost during an internal overflow.
#	Test("ssh", TESTS_ROOT + "ssh/ssh", [
#		Trace("interactive_login_attempt", TESTS_ROOT + "ssh/interactive_login_attempt.pt", "0x55555555e000", "0xa000"),
#	]),
#	Test("clang", TESTS_ROOT + "clang/clang", [
#		Trace("compile_simple_c_part_1", TESTS_ROOT + "clang/compile_simple_c_1.pt", "0x400000", "0x0"),
#		Trace("compile_simple_c_part_2", TESTS_ROOT + "clang/compile_simple_c_2.pt", "0x400000", "0x0"),
#	]),
#	Test("honey_mirror_1", TESTS_ROOT + "honey_mirror_1/honey_mirror", [
#		Trace("clang_huge", TESTS_ROOT + "honey_mirror_1/clang_huge.pt", "0x401000", "0x1000"),
#		Trace("bash", TESTS_ROOT + "honey_mirror_1/bash.pt", "0x401000", "0x1000"),
#	]),
]


for test in tests:
	#Try and build the target
	if not generate_test_hive(test):
		print(f"[!!!] Skipping all traces for test {test.display_name} because it failed to generate a hive")
		continue
		
	for trace in test.traces:
		perform_libipt_audit(test, trace)

print("-" * 60)
success_count = 0
print("TEST RESULTS:")
for test in tests:
	if test.print_test_result_and_return_summary():
		success_count += 1
print("-" * 60)
print(f"Summary: {str(success_count)}/{str(len(tests))} targets passed")
