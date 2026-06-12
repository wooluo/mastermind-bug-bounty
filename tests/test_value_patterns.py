"""
tests/test_value_patterns.py — Tests for expanded value extraction patterns
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.linkage.value_linkage import ValueLinkageEngine, VALUE_PATTERNS, LinkagePriority


def test_jwt_pattern():
    """Test JWT token extraction."""
    engine = ValueLinkageEngine()

    test_content = '''
    const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    fetch('/api/user', { headers: { Authorization: token }});
    '''

    values = engine._extract_values_from_content(test_content, "test.js")
    jwt_values = [v for v in values if v.source_param == 'jwt']

    assert len(jwt_values) > 0, "Should extract JWT token"
    assert jwt_values[0].priority == LinkagePriority.CRITICAL, "JWT should be CRITICAL"
    print("  ✓ JWT pattern works")


def test_aws_key_pattern():
    """Test AWS key extraction."""
    engine = ValueLinkageEngine()

    test_content = '''
    const aws = {
        accessKeyId: "AKIAIOSFODNN7EXAMPLE",
        secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    };
    '''

    values = engine._extract_values_from_content(test_content, "config.js")
    aws_keys = [v for v in values if v.source_param == 'aws_key']

    assert len(aws_keys) > 0, "Should extract AWS key"
    assert aws_keys[0].priority == LinkagePriority.CRITICAL, "AWS key should be CRITICAL"
    print("  ✓ AWS key pattern works")


def test_github_token_pattern():
    """Test GitHub token extraction."""
    engine = ValueLinkageEngine()

    # Use valid GitHub token format (ghp_ + 36 chars)
    test_content = '''
    const github = new GitHub({
        token: "ghp_1234567890abcdefghijklmnopqrstuvwx"
    });
    '''

    values = engine._extract_values_from_content(test_content, "github.js")
    github_tokens = [v for v in values if v.source_param == 'github_token']

    assert len(github_tokens) > 0, "Should extract GitHub token"
    assert github_tokens[0].priority == LinkagePriority.CRITICAL, "GitHub token should be CRITICAL"
    print("  ✓ GitHub token pattern works")


def test_graphql_operation_pattern():
    """Test GraphQL operation extraction."""
    engine = ValueLinkageEngine()

    test_content = '''
    const GET_USER = gql`
        query GetUser($id: ID!) {
            user(id: $id) {
                name
                email
            }
        }
    `;

    mutation UpdateUser($input: UserInput!) {
        updateUser(input: $input) {
            id
        }
    }
    '''

    values = engine._extract_values_from_content(test_content, "graphql.js")
    graphql_ops = [v for v in values if v.source_param == 'graphql_operation']

    assert len(graphql_ops) > 0, "Should extract GraphQL operations"
    print("  ✓ GraphQL operation pattern works")


def test_s3_bucket_pattern():
    """Test S3 bucket extraction."""
    engine = ValueLinkageEngine()

    test_content = '''
    const s3Config = {
        bucket: "my-app-bucket-12345",
        region: "us-east-1"
    };

    const url = "https://my-app-bucket-12345.s3.amazonaws.com/uploads/file.pdf";
    '''

    values = engine._extract_values_from_content(test_content, "s3.js")
    s3_buckets = [v for v in values if v.source_param == 's3_bucket']

    assert len(s3_buckets) > 0, "Should extract S3 bucket"
    assert s3_buckets[0].priority == LinkagePriority.HIGH, "S3 bucket should be HIGH"
    print("  ✓ S3 bucket pattern works")


def test_database_url_pattern():
    """Test database URL extraction."""
    engine = ValueLinkageEngine()

    test_content = '''
    const dbUrl = "postgres://user:password@localhost:5432/mydb";
    DATABASE_URL="mongodb://cluster0-shard-00-00.mongodb.net:27017"
    '''

    values = engine._extract_values_from_content(test_content, "database.js")
    db_urls = [v for v in values if v.source_param == 'database_url']

    assert len(db_urls) > 0, "Should extract database URL"
    assert db_urls[0].priority == LinkagePriority.CRITICAL, "Database URL should be CRITICAL"
    print("  ✓ Database URL pattern works")


def test_internal_ip_pattern():
    """Test internal IP extraction."""
    engine = ValueLinkageEngine()

    test_content = '''
    const config = {
        adminServer: "10.0.1.50",
        database: "192.168.1.100",
        cache: "172.16.0.1"
    };
    '''

    values = engine._extract_values_from_content(test_content, "internal.js")
    internal_ips = [v for v in values if v.source_param == 'internal_ip']

    assert len(internal_ips) > 0, "Should extract internal IP"
    assert internal_ips[0].priority == LinkagePriority.LOW, "Internal IP should be LOW"
    print("  ✓ Internal IP pattern works")


def test_csrf_token_pattern():
    """Test CSRF token extraction."""
    engine = ValueLinkageEngine()

    test_content = '''
    <form>
        <input type="hidden" name="csrf_token" value="abc123def456ghi789jkl012" />
        <input type="hidden" name="_token" value="xyz789ghi012jkl345mno678" />
    </form>

    const csrf = "csrf_token=abc123def456ghi789jkl012";
    '''

    values = engine._extract_values_from_content(test_content, "form.html")
    csrf_tokens = [v for v in values if v.source_param == 'csrf_token']

    assert len(csrf_tokens) > 0, "Should extract CSRF token"
    assert csrf_tokens[0].priority == LinkagePriority.CRITICAL, "CSRF token should be CRITICAL"
    print("  ✓ CSRF token pattern works")


def test_all_patterns_defined():
    """Test that all critical patterns are defined."""
    required_patterns = [
        'jwt', 'api_key', 'aws_key', 'google_api_key', 'github_token',
        'slack_token', 'stripe_key', 'bearer_token', 'auth_token',
        'refresh_token', 'csrf_token', 'secret', 'database_url',
    ]

    for pattern in required_patterns:
        assert pattern in VALUE_PATTERNS, f"Missing pattern: {pattern}"

    print(f"  ✓ All {len(required_patterns)} required patterns defined")


def run_all_tests():
    """Run all pattern tests."""
    print("\n" + "="*60)
    print("VALUE EXTRACTION PATTERN TESTS")
    print("="*60 + "\n")

    tests = [
        test_jwt_pattern,
        test_aws_key_pattern,
        test_github_token_pattern,
        test_graphql_operation_pattern,
        test_s3_bucket_pattern,
        test_database_url_pattern,
        test_internal_ip_pattern,
        test_csrf_token_pattern,
        test_all_patterns_defined,
    ]

    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"  ✗ {test.__name__} failed: {e}")
            return False
        except Exception as e:
            print(f"  ✗ {test.__name__} error: {e}")
            import traceback
            traceback.print_exc()
            return False

    print("\n" + "="*60)
    print(f"ALL TESTS PASSED ✓ ({len(tests)} tests)")
    print("="*60 + "\n")
    return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
