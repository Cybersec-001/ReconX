"""First-run admin seeding: an admin account appears only when env credentials are set."""
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROBE = (
    "import app\n"
    "with app.app.app_context():\n"
    "    u = app.User.query.filter_by(username='siteadmin').first()\n"
    "    print('ADMIN_OK' if (u and u.is_admin and u.check_password('admin-pass-123')) else 'ADMIN_MISSING')\n"
)


def _run_bootstrap(tmp_path, extra_env):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": REPO_ROOT,
        "SECRET_KEY": "bootstrap-test-secret-key",
        "DATABASE_URL": "sqlite:///" + str(tmp_path / "boot.db"),
    }
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120,
    )


def test_admin_seeded_when_credentials_provided(tmp_path):
    result = _run_bootstrap(tmp_path, {"ADMIN_USERNAME": "siteadmin",
                                       "ADMIN_PASSWORD": "admin-pass-123"})
    assert result.returncode == 0, result.stderr
    assert "ADMIN_OK" in result.stdout


def test_no_admin_without_credentials(tmp_path):
    result = _run_bootstrap(tmp_path, {})
    assert result.returncode == 0, result.stderr
    assert "ADMIN_MISSING" in result.stdout
