#!/usr/bin/env python3

"""
Honeybee Project Unit Tester

---
Author: Allison Husain <$first.$last@berkeley.edu>
Date: December 31st, 2020
"""
import subprocess

TESTS_ROOT = "../honeybee_unittest_data/"
HONEY_MIRROR_PATH = "cmake-build-debug/honey_mirror"
ANALYZE_TEMP_PATH = "/tmp/analyze"

class Test:
	__slots__ = ["display_name", "binary_path", "traces", "build_exit_code"]
	def __init__(self, display_name, binary_path, traces):
		self.display_name = display_name
		self.binary_path = binary_path
		self.traces = traces
		
		self.build_exit_code = -1
	
	def print_test_result_and_return_summary(self):
		"""
		Prints the results of this test and all of its traces
		"""
		overall_success = self.build_exit_code == 0
		print(f"[[{self.display_name}]]\n* Target build code = {str(self.build_exit_code)}")
		
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
		

def build_test_analyze_target(test):
	"""
	Compiles the analyze target for a given test. 
	Returns true on success.
	"""
	print(f"[***] Running build on {test.display_name}")
	task = subprocess.Popen([HONEY_MIRROR_PATH, test.binary_path, ANALYZE_TEMP_PATH, "."])
	task.communicate() #wait
	test.build_exit_code = task.returncode
	if task.returncode != 0:
		print("Build {test.display_name} failed with code {str(task.returncode)}")
		return False
	return True
	
def perform_libipt_audit(test, trace):
	"""
	Performs a libipt audit to verify that the decoder and mirror are working correctly.
	Requires that the analyze target has been built.
	Returns true on success.
	"""
	print(f"[***] Running libipt audit on {test.display_name}.{trace.display_name}")
	task = subprocess.Popen([ANALYZE_TEMP_PATH, "-a", "-s", trace.sideband_load_address, "-o", trace.sideband_offset, "-t", trace.trace_path, "-b", test.binary_path])
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
	Test("ssh", TESTS_ROOT + "ssh/ssh", [
		Trace("interactive_login_attempt", TESTS_ROOT + "ssh/interactive_login_attempt.pt", "0x55555555e000", "0xa000"),
	]),
]


for test in tests:
	#Try and build the target
	if not build_test_analyze_target(test):
		print(f"[!!!] Skipping all traces for test {test.display_name} because it failed to build")
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
