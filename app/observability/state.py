"""Bounded measured request windows and local SLA alerts; no synthetic samples."""
from collections import deque
from math import ceil
from threading import Lock
import time

from app.db.store import now


class ObservationWindow:
    def __init__(self,clock=time.time,max_samples=8192):
        self.clock=clock;self.lock=Lock()
        self.requests=deque(maxlen=max_samples);self.cache=deque(maxlen=max_samples)

    def request(self,route,status,seconds):
        if not route.startswith('/api/') or route=='/api/v1/observability':return
        with self.lock:self.requests.append((self.clock(),int(status),max(0,float(seconds))))

    def cache_lookup(self,hit):
        with self.lock:self.cache.append((self.clock(),bool(hit)))

    def snapshot(self,queue_depth,ai_health):
        cutoff=self.clock()-300
        with self.lock:
            while self.requests and self.requests[0][0]<cutoff:self.requests.popleft()
            while self.cache and self.cache[0][0]<cutoff:self.cache.popleft()
            requests=list(self.requests);cache=list(self.cache)
        durations=sorted(row[2] for row in requests)
        return {'measured_at':now(),'window_seconds':300,'max_window_samples':self.requests.maxlen,
            'api_samples':len(requests),'api_p95_seconds':durations[ceil(len(durations)*.95)-1] if durations else None,
            'api_error_rate_percent':100*sum(row[1]>=500 for row in requests)/len(requests) if requests else None,
            'cache_samples':len(cache),'cache_hit_rate_percent':100*sum(row[1] for row in cache)/len(cache) if cache else None,
            'queue_depth':queue_depth,'ai_configured':bool(ai_health.get('configured')),
            'ai_available':ai_health.get('available'),'ai_last_check_timestamp':ai_health.get('last_check_timestamp',0),
            'ai_circuit_open':bool(ai_health.get('circuit_open'))}

    def evaluate_alerts(self,store,config,snapshot):
        """Called every scheduler tick; record transitions, not repeated notifications."""
        minimum=config.get('alert_min_samples',20)
        policies={
            'api_latency':(snapshot['api_samples']>=minimum and snapshot['api_p95_seconds']>config['alert_latency_p95_seconds'],
                           snapshot['api_p95_seconds'],config['alert_latency_p95_seconds']),
            'api_errors':(snapshot['api_samples']>=minimum and snapshot['api_error_rate_percent']>config['alert_error_rate_percent'],
                          snapshot['api_error_rate_percent'],config['alert_error_rate_percent']),
            'cache_hit_rate':(snapshot['cache_samples']>=minimum and snapshot['cache_hit_rate_percent']<config['alert_cache_hit_rate_percent'],
                              snapshot['cache_hit_rate_percent'],config['alert_cache_hit_rate_percent']),
            'queue_depth':(snapshot['queue_depth']>config['alert_queue_depth'],snapshot['queue_depth'],config['alert_queue_depth']),
            'ai_unavailable':(snapshot['ai_configured'] and (snapshot['ai_available'] is False or snapshot['ai_circuit_open']),
                              snapshot['ai_available'],True)}
        transitions=[]
        for name,(firing,value,threshold) in policies.items():
            old=store.get('alert',name)
            status='firing' if firing and config.get('alerts_enabled',True) else 'resolved'
            if not old and status=='resolved':continue
            record={**(old or {}),'id':name,'status':status,'observed_value':value,'threshold':threshold,
                    'last_evaluated_at':now(),'evaluation_interval_seconds':10,'channel':'Smart Patch UI events and authenticated API'}
            if not old or old['status']!=status:
                record['changed_at']=now();transitions.append(record)
                store.audit('sla.alert_'+status,'Smart Patch '+name.replace('_',' ')+' alert '+status,
                    details={'alert_id':name,'value':value,'threshold':threshold},severity='warning' if firing else 'info')
            store.put('alert',name,record)
        store.put('status','observability',snapshot)
        return transitions
