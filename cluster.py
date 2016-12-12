#!/usr/bin/python -u

import scipy.cluster
import sys
import math
import multiprocessing
from scipy.cluster.vq import vq,kmeans,whiten

def read_data(filename):
    res = []
    for line in open(filename).readlines():
        res.append([float(i) for i in line.strip().split()])
    return res

def count_elem(lst):
    res = {}
    for elem in lst:
        if elem in res.keys():
            res[elem] += 1
        else:
            res[elem] = 1
    return res


def do_clustering(data):
    
    # hierarchical clustering
    dist_matrix = scipy.cluster.hierarchy.distance.pdist(data, 'euclidean')
    Z = scipy.cluster.hierarchy.linkage(dist_matrix, method='average')
    cluster = scipy.cluster.hierarchy.fcluster(Z, t=1.0)
    k = max(cluster)
    #print "result of hierarchy clustering:", k, "clusters"
    
    #wdata = whiten(data)
    wdata = data
    cr = scipy.cluster.vq.kmeans(wdata, k)[0]
    #print cr[0]
    label = vq(wdata, cr)
    ct = count_elem(list(label[0]))
    res = []
    for key in ct:
        res.append([(cr[key][0], cr[key][1]), ct[key]/float(len(data))*100])

    return sorted(res, key=lambda(x):x[1], reverse=True)

def distance(p1, p2):
    return math.sqrt((p1[0] - p2[0])**2 + (p1[1] - p2[1])**2)

def close_enough(p1, p2):
    distance_threshold = 20
    if p1[0] == 0.0 and p2[0] != 0.0  or p1[0] != 0.0 and p2[0] == 0.0:
        return False
    if p1[1] == 0.0 and p2[1] != 0.0  or p1[1] != 0.0 and p2[1] == 0.0:
        return False
    if distance(p1, p2) <= distance_threshold:
        return True
    else:
        return False
    

def is_similar_cluster(clstr1, clstr2):
    ratio_threshold = 30
    total_match_threshold = 2

    total_ratio1 = 0
    total_ratio2 = 0
    total_match = 0
    match_index1 = set()
    match_index2 = set()
    for index1,c1 in enumerate(clstr1[:10]):
        centroid1, ratio1 = c1
        for index2,c2 in enumerate(clstr2[:10]):
            centroid2, ratio2 = c2
            if close_enough(centroid1, centroid2):
                match_index1.add(index1)
                match_index2.add(index2)
                total_match += 1
                break

    for i in match_index1:
        total_ratio1 += clstr1[i][1]
    for i in match_index2:
        total_ratio2 += clstr2[i][1]

    if total_ratio1 >= ratio_threshold and total_ratio2 >= ratio_threshold and total_match >= total_match_threshold:
        print " ============ similar clusters found ================"
        print_cluster(clstr1)
        print " ============ ====================== ================"
        print_cluster(clstr2)
        print " ============ ====================== ================"
        print match_index1
        print match_index2
        print " ============ ====================== ================"
        return True
    else:
        return False

def print_cluster(clstr):
    for i, c in enumerate(clstr):
        centroid, ratio = c
        x,y = centroid
        print "(%9.2f, %9.2f) %4.1f" % (x, y, ratio),
        if (i+1) % 5 == 0:
            print
    if (i+1) % 5 != 0:
        print
    
def read_frigate_log(logfilenames):
    res = {}
    total_lines = 0
    for logfilename in logfilenames:
        for line in open(logfilename):
            spline = line.strip().split()
            up = spline[7]
            down = spline[8]
            ipport = spline[5]
            ip = ipport.split(':')[0]

            if ip in res.keys():
                res[ip].append([float(up), float(down)])
            else:
                res[ip] = [[float(up), float(down)],]
            total_lines += 1
            if total_lines % 10000 == 0:
                print "%d lines read" % total_lines;

    for ip in res.keys():
        if any([i[1] for i in res[ip]]) == False:
            res.pop(ip)

    return res

def parse_line(line):
    # 1.2.3.4   11,22  33,44  55,66
    # 1.2.3.5   77,88  99,10
    # ... 
    spline = line.split()
    ip = spline[0]
    cs = []
    for c in spline[1:]:
        cs.append([float(i) for i in c.split(',')])
    return ip, cs

def compare_cluster(lines, thread_i, probe_clstrs):
    for line in lines:
        ip_addr, data = parse_line(line)
        if not ip_addr:
            continue

        # few logs, or too many logs, skip
        if len(data) < 5 or len(data) > 10000:
            continue
        cmp_clstr = do_clustering(data)
        if len(cmp_clstr) < 3: continue
        for probe_clstr in probe_clstrs:
            if is_similar_cluster(probe_clstr, cmp_clstr):
                #print 'P:', probe_clstr
                #print 'C:', cmp_clstr
                print "Suspicious IP: ", ip_addr
                break

def get_lines(f, n):
    res = []
    eof = False
    for i in range(n):
        line = f.readline()
        if line:
            res.append(line)
        else:
            eof = True
            break
    return res, eof

def go_process(inputfilename, probe_clstrs):
    #n_process = multiprocessing.cpu_count()
    n_process = 2
    n_lines_per_process = 3000
    f = open(inputfilename)
    total = 0

    while True:
        process_list = []
        for process_i in range(n_process):
            lines, eof = get_lines(f, n_lines_per_process)
            p = multiprocessing.Process(target = compare_cluster, args=(lines, process_i, probe_clstrs))
            process_list.append(p)
            p.start()
            if eof: break

        for p in process_list:
            p.join()
        total += n_process * n_lines_per_process
        print "%d IP scanned" % total

        if eof: break

def scan_probes(filenames):
    print "Reading known probes logs ..."
    probe_datas = read_frigate_log(filenames)
    probe_clstrs = []
    clustering_log_num_threshold = 10
    for ip in probe_datas:
        if len(probe_datas[ip]) <= clustering_log_num_threshold: 
            print "skip IP: %s (has less than %d logs)" % (ip, clustering_log_num_threshold)
            continue
        else:
            print "Clustering known probe IP: %s ..." % (ip),
            probe_clstr = do_clustering(probe_datas[ip])
            probe_clstrs.append(probe_clstr)
            print "OK"
            print_cluster(probe_clstr)
    print "Done"
    return probe_clstrs

def write_input_file(fres):
    """ for test purpose only """
    filename = "testinput.txt"
    f = open(filename, "w")
    for ip in fres.keys():
        data = fres[ip]
        f.write("%s " % ip)
        f.write("%s\n" % (" ".join([",".join([str(int(i)) for i in p]) for p in data])))

    f.close()
    return filename

def main():
    probe_clstrs = scan_probes(sys.argv[1:2])
    
    print "Reading frigate logs..."
    fres = read_frigate_log(sys.argv[2:])
    inputfilename = write_input_file(fres)
    print "Done"
    
    print "Comparing ..."
    go_process(inputfilename, probe_clstrs)

def main2():
    print "Reading known probes logs ..."
    probe_datas = read_frigate_log(sys.argv[1:2])
    probe_clstrs = []
    clustering_log_num_threshold = 10
    for ip in probe_datas:
        if len(probe_datas[ip]) <= clustering_log_num_threshold: 
            print "skip IP: %s (has less than %d logs)" % (ip, clustering_log_num_threshold)
            continue
        else:
            print "Clustering known probe IP: %s ..." % (ip),
            probe_clstr = do_clustering(probe_datas[ip])
            probe_clstrs.append(probe_clstr)
            print "OK"
            print_cluster(probe_clstr)
    print "Done"
    
    print "Reading frigate logs..."
    fres = read_frigate_log(sys.argv[2:])
    print "Done"
    
    print "Comparing ..."
    for ip in fres.keys():
        data = fres[ip]
        if len(data) < 3 or len(data) > 10000:
            #print ip, "skip"
            continue
        cmp_clstr = do_clustering(fres[ip])
        if len(cmp_clstr) < 3: continue
        for probe_clstr in probe_clstrs:
            if is_similar_cluster(probe_clstr, cmp_clstr):
                #print 'P:', probe_clstr
                #print 'C:', cmp_clstr
                print "Suspicious IP: ", ip
                break
        #else:
        #    print ip, "safe"

main()
