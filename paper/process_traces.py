#!/usr/bin/env python3

import os

class Trace:
	__slots__ = ["blocks", "edges", "timestamp"]
	def __init__(self, blocks, edges, timestamp):
		self.blocks = blocks
		self.edges = edges
		self.timestamp = timestamp
		
	def __repr__(self):
		return self.__str__()
	
	def __str__(self):
		return f"<Trace: blocks={str(len(self.blocks))}, edges={str(len(self.edges))}, timestamp={str(self.timestamp)}"

def read_int_line(f):
	return int(f.readline().strip())

def process_trace(trace_path):
	timestamp = os.path.getmtime(trace_path.replace(".trace", ""))
	f = open(trace_path, "r")

	block_count = read_int_line(f)
	edge_count = read_int_line(f)
		
	blocks = set()
	edges = set()
	for i in range(0, block_count):
		blocks.add(read_int_line(f))
	for i in range(0, edge_count):
		edges.add(read_int_line(f))
	
	return Trace(blocks, edges, timestamp)

def generate_unique_block_sets(traces):
	"""
	Generates unique block and edge sets given a set of traces
	"""
	
	unique_blocks = set()
	unique_edges = set()
	
	for trace in traces:
		unique_blocks.update(trace.blocks)
		unique_edges.update(trace.edges)
	
	return unique_blocks, unique_edges

def report_traces(traces):
	trace_seen_blocks = set()
	trace_seen_edges = set()
	unique_blocks_count_dt = []
	unique_edges_count_dt = []
	for trace in traces:
		trace_seen_blocks.update(trace.blocks)
		trace_seen_edges.update(trace.edges)
		unique_blocks_count_dt.append(len(trace_seen_blocks))
		unique_edges_count_dt.append(len(trace_seen_edges))
	
#	print(traces)
#	start_ts = traces[0].timestamp
#	print("Trace time (s),Unique Blocks,Unique Edges")
#	for i in range(len(unique_blocks_count_dt)):
#		print(traces[i].timestamp - start_ts, unique_blocks_count_dt[i], unique_edges_count_dt[i], sep=",")
#	print(unique_blocks_count_dt)
#	print(unique_edges_count_dt)
#	print("Unique blocks:", len(trace_seen_blocks), "Unique edges:", len(trace_seen_edges))
		
	return unique_blocks_count_dt, unique_edges_count_dt


def get_sorted_traces(trace_dir):
	trace_paths = [os.path.join(trace_dir, trace) for trace in filter(lambda s: s.endswith(".trace"), os.listdir(trace_dir))]
	traces = []
	for trace_path in trace_paths:
		traces.append(process_trace(trace_path))
	
	traces = sorted(traces, key=lambda trace: trace.timestamp)
	
	return traces

def main():
	paths = ["/Users/allison/Downloads/coverage_exp1/coverage_dir_honeybee_edges", "/Users/allison/Downloads/coverage_exp2/coverage_dir_fuzz_pcap_honeybee/", "/Users/allison/Downloads/coverage_exp3/coverage_dir_fuzz_pcap_honeybee/", "/Users/allison/Downloads/coverage_exp1/coverage_dir_inst", "/Users/allison/Downloads/coverage_exp2/coverage_dir_fuzz_pcap_inst/", "/Users/allison/Downloads/coverage_exp3/coverage_dir_fuzz_pcap_inst/"]
	runs = [get_sorted_traces(path) for path in paths]
	trace_start_ts = [run[0].timestamp for run in runs]
	dt = [report_traces(run) for run in runs]
	
	maps = {}
	for run_i in range(len(runs)):
		run = runs[run_i]
		for trace in run:
			local_ts = trace.timestamp - trace_start_ts[run_i]
			if local_ts not in maps:
				a = [0 for i in range(len(runs))]
				a[run_i] = len(trace.edges)
				maps[local_ts] = a
			else:
				a = max(len(trace.edges), maps[local_ts][run_i])
	
	print("Timestamp (s),Honeybee 1 (edge),Honeybee 2 (edge),Honeybee 3 (edge),Clang SW 1 (edge+block+cmp),Clang SW 2 (edge+block+cmp),Clang SW 3 (edge+block+cmp)")
	last_key = 0
	for key in sorted(maps):
		a = maps[key]
		for i in range(len(a)):
			if a[i]:
				a[i] = max(a[i], maps[last_key][i])
			else:
				a[i] = maps[last_key][i]
		last_key = key
		print(key, *a, sep=",")
		
#	
#	while True:
#		selected
#		for run_i in range(len(runs)):
#			
#	
#	print(trace_start_ts)
	

main()
	