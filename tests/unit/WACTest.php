<?php declare(strict_types=1);

namespace Pdsinterop\Solid\Auth;

use Laminas\Diactoros\Uri;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Pdsinterop\Solid\Auth\WAC
 * @covers ::__construct
 */
class WACTest extends TestCase
{
    /**
     * @testdox WAC should advertise the ACL resource of the resource itself, relative to the resource
     *
     * @covers ::getAclLinkTarget
     *
     * @dataProvider provideResourceUris
     */
    public function testGetAclLinkTarget(string $resourceUri, string $expected, string $expectedAclUri): void
    {
        $wac = new WAC(null, null);

        $actual = $wac->getAclLinkTarget(new Uri($resourceUri));

        $this->assertSame($expected, $actual);
    }

    /**
     * @testdox WAC should advertise an ACL link that resolves to the resource's own ACL resource, not to the ACL of its container
     *
     * @covers ::getAclLinkTarget
     *
     * @dataProvider provideResourceUris
     */
    public function testAclLinkResolvesToOwnAcl(string $resourceUri, string $target, string $expectedAclUri): void
    {
        $wac = new WAC(null, null);

        $link = $wac->getAclLinkTarget(new Uri($resourceUri));

        // A relative reference that is a single path segment resolves against the "directory" of the resource
        $resolved = substr($resourceUri, 0, strrpos($resourceUri, '/') + 1) . $link;

        $this->assertSame($expectedAclUri, $resolved);
    }

    public static function provideResourceUris(): array
    {
        return [
            'root container' => ['https://pod.example/', '.acl', 'https://pod.example/.acl'],
            'container' => ['https://pod.example/private/', '.acl', 'https://pod.example/private/.acl'],
            'resource in container' => ['https://pod.example/private/note.ttl', 'note.ttl.acl', 'https://pod.example/private/note.ttl.acl'],
            'resource at root' => ['https://pod.example/note.ttl', 'note.ttl.acl', 'https://pod.example/note.ttl.acl'],
            'percent-encoded name' => ['https://pod.example/private/my%20note.ttl', 'my%20note.ttl.acl', 'https://pod.example/private/my%20note.ttl.acl'],
            'ACL resource of a resource' => ['https://pod.example/private/note.ttl.acl', 'note.ttl.acl', 'https://pod.example/private/note.ttl.acl'],
            'ACL resource of a container' => ['https://pod.example/private/.acl', '.acl', 'https://pod.example/private/.acl'],
        ];
    }
}
