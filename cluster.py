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
    print "result of hierarchy clustering:", k, "clusters"
    
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
    distance_threshold = 20
    ratio_threshold = 50

    total_ratio1 = 0
    total_ratio2 = 0
    for c1 in clstr1[:5]:
        centroid1, ratio1 = c1
        for c2 in clstr2[:5]:
            centroid2, ratio2 = c2
            if distance(centroid1, centroid2) < distance_threshold:
                total_ratio1 += ratio1
                total_ratio2 += ratio2
                break

    if total_ratio1 > ratio_threshold and total_ratio2 > ratio_threshold:
        return True
    else:
        return False

data1 = read_data(sys.argv[1])
data2 = read_data(sys.argv[2])
clstr1 = do_clustering(data1)
clstr2 = do_clustering(data2)

print clstr1
print clstr2

print is_similar_cluster(clstr1, clstr2)


