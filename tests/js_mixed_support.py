"""Build-only owned mixed fixtures; no application imports or validation."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_JS = ROOT / 'samples/multilang/javascript_mixed'


def build_sample(mixed, tmp, sample_dir, files, *, project='project.json', seed=4242):
    project_dir = Path(tmp) / 'project'
    project_dir.mkdir(parents=True, exist_ok=True)
    for name in files:
        shutil.copy2(Path(sample_dir) / name, project_dir / name)
    output = Path(tmp) / '.runs' / 'out'
    return (mixed.build_project(project_dir / project, output, workspace_root=Path(tmp), seed=seed),
            output, project_dir)
