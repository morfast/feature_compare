#!/usr/bin/python

import scipy.cluster
import sys
import math
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

def is_similar_cluster(clstr1, clstr2):
    distance_threshold = 10
    ratio_threshold = 50
    total_match_threshold = 2

    total_ratio1 = 0
    total_ratio2 = 0
    total_match = 0
    match_index1 = set()
    match_index2 = set()
    for index1,c1 in enumerate(clstr1[:5]):
        centroid1, ratio1 = c1
        for index2,c2 in enumerate(clstr2[:5]):
            centroid2, ratio2 = c2
            if distance(centroid1, centroid2) <= distance_threshold:
                match_index1.add(index1)
                match_index2.add(index2)
                total_match += 1
                break

    for i in match_index1:
        total_ratio1 += clstr1[i][1]
    for i in match_index2:
        total_ratio2 += clstr2[i][1]

    if total_ratio1 >= ratio_threshold and total_ratio2 >= ratio_threshold and total_match >= total_match_threshold:
        return True
    else:
        return False

def read_frigate_log(logfilename):
    res = {}
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

    return res

def test():
    data1 = read_data(sys.argv[1])
    data2 = read_data(sys.argv[2])
    clstr1 = do_clustering(data1)
    clstr2 = do_clustering(data2)
    
    print clstr1
    print clstr2
    
    print is_similar_cluster(clstr1, clstr2)

def main():
    print "Reading known probes logs ..."
    probe_datas = read_frigate_log(sys.argv[1])
    probe_clstrs = []
    for ip in probe_datas:
        if len(probe_datas[ip]) <= 10: continue
        print "Clustering probe IP:", ip
        probe_clstr = do_clustering(probe_datas[ip])
        probe_clstrs.append(probe_clstr)
        #print probe_clstr
        #print
    print "Done"
    
    print "Reading frigate logs...",
    fres = read_frigate_log(sys.argv[2])
    print "Done"
    
    for ip in fres.keys():
        data = fres[ip]
        if len(data) < 3 or len(data) > 10000:
            #print ip, "skip"
            continue
        cmp_clstr = do_clustering(fres[ip])
        if len(cmp_clstr) < 3: continue
        for probe_clstr in probe_clstrs:
            if is_similar_cluster(probe_clstr, cmp_clstr):
                print 'P:', probe_clstr
                print 'C:', cmp_clstr
                print ip, "dangerous"
                print
                break
        #else:
        #    print ip, "safe"

main()
