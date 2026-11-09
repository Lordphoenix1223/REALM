"""Broker-owned local observation records, never native evidence authority.

Uses the existing Worker journal and effect engine. The controller supplies only
requests; identities, versions, failures and results are observed by the broker.
Existing cold development audit does not accept these new events as a qualified
history. No deserializer can turn the resulting journal into native capability.
"""
import os
from pathlib import Path

import coding_worker as worker


class ObservedBroker:
    def __init__(self, broker, binding):
        if (set(binding) != {'run_id', 'execution_id', 'challenge_root', 'task_sha256', 'worker_sha256'}
                or any(type(v) is not str or len(v) != 64 or set(v) - set('0123456789abcdef') for v in binding.values())
                or binding['task_sha256'] != worker.digest(worker.encoded(worker.contract()))
                or binding['worker_sha256'] != worker.digest(Path(worker.__file__).read_bytes())):
            raise ValueError('exact supported task/source/run binding required')
        self.broker = broker
        self.binding = dict(binding)
        self.source = worker.digest(Path(__file__).read_bytes())

    def namespace(self):
        info = os.fstat(self.broker.fd)
        # This is an actual broker observation of the anchored directory. It is
        # not learned from controller-supplied names or pass/fail summaries.
        names = sorted(os.listdir(self.broker.fd))
        objects = {}
        for name in worker.FILES:
            try:
                st = os.stat(name, dir_fd=self.broker.fd, follow_symlinks=False)
                objects[name] = {'device': st.st_dev, 'inode': st.st_ino, 'mode': st.st_mode,
                                 'size': st.st_size, 'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns}
            except OSError as error:
                objects[name] = {'errno': error.errno}
        view = {'directory': {'device': info.st_dev, 'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns,
                              'ctime_ns': info.st_ctime_ns}, 'names': names, 'objects': objects}
        return {**view, 'snapshot_sha256': worker.digest(worker.encoded(view))}

    def request(self, request):
        before = self.namespace()
        self.broker.event({'controller_observation': {'binding': self.binding,
            'observer_source_sha256': self.source, 'phase': 'request',
            'request_hex': worker.encoded(request).hex(), 'namespace': before, 'authority': 'NONE'}})
        try:
            result = self.broker.request(request)
        except (ValueError, OSError, UnicodeError) as error:
            self.broker.event({'controller_observation': {'binding': self.binding,
                'observer_source_sha256': self.source, 'phase': 'result', 'status': 'REFUSE',
                'error_type': type(error).__name__, 'errno': getattr(error, 'errno', None),
                'error': str(error), 'namespace': self.namespace(), 'authority': 'NONE'}})
            raise
        self.broker.event({'controller_observation': {'binding': self.binding,
            'observer_source_sha256': self.source, 'phase': 'result', 'status': 'TOOL_RESULT',
            'result_hex': worker.encoded(result).hex(), 'namespace': self.namespace(), 'authority': 'NONE'}})
        return result
