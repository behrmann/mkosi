# SPDX-License-Identifier: LGPL-2.1+

import argparse
import itertools
import operator
import tempfile
from contextlib import contextmanager
from os import chdir, getcwd
from pathlib import Path
from textwrap import dedent
from typing import Iterator, List, Optional

import pytest

from mkosi.util import Compression, Distribution, Verb
from mkosi.config import MkosiConfigParser, MkosiConfig, MkosiArgs


@contextmanager
def cd_temp_dir() -> Iterator[None]:
    old_dir = getcwd()

    with tempfile.TemporaryDirectory() as tmp_dir:
        chdir(tmp_dir)
        try:
            yield
        finally:
            chdir(old_dir)


def parse(argv: Optional[List[str]] = None) -> tuple[MkosiArgs, tuple[MkosiConfig, ...]]:
    return MkosiConfigParser().parse(argv)


def test_parse_load_verb() -> None:
    with cd_temp_dir():
        assert parse(["build"])[0].verb == Verb.build
        assert parse(["clean"])[0].verb == Verb.clean
        with pytest.raises(SystemExit):
            parse(["help"])
        assert parse(["genkey"])[0].verb == Verb.genkey
        assert parse(["bump"])[0].verb == Verb.bump
        assert parse(["serve"])[0].verb == Verb.serve
        assert parse(["build"])[0].verb == Verb.build
        assert parse(["shell"])[0].verb == Verb.shell
        assert parse(["boot"])[0].verb == Verb.boot
        assert parse(["qemu"])[0].verb == Verb.qemu
        with pytest.raises(SystemExit):
            parse(["invalid"])


def test_os_distribution() -> None:
    with cd_temp_dir():
        for dist in Distribution:
            assert parse(["-d", dist.name])[1][0].distribution == dist

        with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
            parse(["-d", "invalidDistro"])
        with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
            parse(["-d"])

        for dist in Distribution:
            config = Path("mkosi.conf")
            config.write_text(f"[Distribution]\nDistribution={dist}")
            assert parse([])[1][0].distribution == dist


def test_parse_config_files_filter() -> None:
    with cd_temp_dir():
        confd = Path("mkosi.conf.d")
        confd.mkdir(0o755)

        (confd / "10-file.conf").write_text("[Content]\nPackages=yes")
        (confd / "20-file.noconf").write_text("[Content]\nPackages=nope")

        assert parse([])[1][0].packages == ["yes"]


def test_compression() -> None:
    with cd_temp_dir():
        assert parse(["--format", "disk", "--compress-output", "False"])[1][0].compress_output == Compression.none


@pytest.mark.parametrize("dist1,dist2", itertools.combinations_with_replacement(Distribution, 2))
def test_match_distribution(dist1: Distribution, dist2: Distribution) -> None:
    with cd_temp_dir():
        parent = Path("mkosi.conf")
        parent.write_text(
            dedent(
                f"""\
                [Distribution]
                Distribution={dist1}
                """
            )
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            dedent(
                f"""\
                [Match]
                Distribution={dist1}

                [Content]
                Packages=testpkg1
                """
            )
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            dedent(
                f"""\
                [Match]
                Distribution={dist2}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            dedent(
                f"""\
                [Match]
                Distribution={dist1} {dist2}

                [Content]
                Packages=testpkg3
                """
            )
        )
        child4 = Path("mkosi.conf.d/child4.conf")
        child4.write_text(
            dedent(
                f"""\
                [Match]
                Distribution=!{dist1}

                [Content]
                Packages=testpkg4
                """
            )
        )
        child5 = Path("mkosi.conf.d/child5.conf")
        child5.write_text(
            dedent(
                f"""\
                [Match]
                Distribution=!{dist2}

                [Content]
                Packages=testpkg5
                """
            )
        )
        child6 = Path("mkosi.conf.d/child6.conf")
        child6.write_text(
            dedent(
                f"""\
                [Match]
                Distribution=!{dist1} !{dist2}

                [Content]
                Packages=testpkg6
                """
            )
        )

        conf = parse([])[1][0]
        assert "testpkg1" in conf.packages
        if dist1 == dist2:
            assert "testpkg2" in conf.packages
        else:
            assert "testpkg2" not in conf.packages
        assert "testpkg3" in conf.packages
        if dist1 == dist2:
            assert "testpkg4" not in conf.packages
            assert "testpkg5" not in conf.packages
        else:
            assert "testpkg4" not in conf.packages
            assert "testpkg5" in conf.packages
        if dist1 == dist2:
            assert "testpkg6" not in conf.packages
        else:
            assert "testpkg6" in conf.packages


@pytest.mark.parametrize(
    "release1,release2", itertools.combinations_with_replacement([36, 37, 38], 2)
)
def test_match_release(release1: int, release2: int) -> None:
    with cd_temp_dir():
        parent = Path("mkosi.conf")
        parent.write_text(
            dedent(
                f"""\
                [Distribution]
                Distribution=fedora
                Release={release1}
                """
            )
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            dedent(
                f"""\
                [Match]
                Release={release1}

                [Content]
                Packages=testpkg1
                """
            )
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            dedent(
                f"""\
                [Match]
                Release={release2}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            dedent(
                f"""\
                [Match]
                Release={release1} {release2}

                [Content]
                Packages=testpkg3
                """
            )
        )
        child4 = Path("mkosi.conf.d/child4.conf")
        child4.write_text(
            dedent(
                f"""\
                [Match]
                Release=!{release1}

                [Content]
                Packages=testpkg4
                """
            )
        )
        child5 = Path("mkosi.conf.d/child5.conf")
        child5.write_text(
            dedent(
                f"""\
                [Match]
                Release=!{release2}

                [Content]
                Packages=testpkg5
                """
            )
        )
        child6 = Path("mkosi.conf.d/child6.conf")
        child6.write_text(
            dedent(
                f"""\
                [Match]
                Release=!{release1} !{release2}

                [Content]
                Packages=testpkg6
                """
            )
        )

        conf = parse([])[1][0]
        assert "testpkg1" in conf.packages
        if release1 == release2:
            assert "testpkg2" in conf.packages
        else:
            assert "testpkg2" not in conf.packages
        assert "testpkg3" in conf.packages
        if release1 == release2:
            assert "testpkg4" not in conf.packages
            assert "testpkg5" not in conf.packages
        else:
            assert "testpkg4" not in conf.packages
            assert "testpkg5" in conf.packages
        if release1 == release2:
            assert "testpkg6" not in conf.packages
        else:
            assert "testpkg6" in conf.packages


@pytest.mark.parametrize(
    "image1,image2", itertools.combinations_with_replacement(
        ["image_a", "image_b", "image_c"], 2
    )
)
def test_match_imageid(image1: str, image2: str) -> None:
    with cd_temp_dir():
        parent = Path("mkosi.conf")
        parent.write_text(
            dedent(
                f"""\
                [Distribution]
                Distribution=fedora
                ImageId={image1}
                """
            )
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            dedent(
                f"""\
                [Match]
                ImageId={image1}

                [Content]
                Packages=testpkg1
                """
            )
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            dedent(
                f"""\
                [Match]
                ImageId={image2}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            dedent(
                f"""\
                [Match]
                ImageId={image1} {image2}

                [Content]
                Packages=testpkg3
                """
            )
        )
        child4 = Path("mkosi.conf.d/child4.conf")
        child4.write_text(
            dedent(
                """\
                [Match]
                ImageId=image*

                [Content]
                Packages=testpkg4
                """
            )
        )
        child5 = Path("mkosi.conf.d/child5.conf")
        child5.write_text(
            dedent(
                f"""\
                [Match]
                ImageId=!{image1}

                [Content]
                Packages=testpkg5
                """
            )
        )
        child6 = Path("mkosi.conf.d/child6.conf")
        child6.write_text(
            dedent(
                f"""\
                [Match]
                ImageId=!{image2}

                [Content]
                Packages=testpkg6
                """
            )
        )
        child7 = Path("mkosi.conf.d/child7.conf")
        child7.write_text(
            dedent(
                """\
                [Match]
                ImageId=!image*

                [Content]
                Packages=testpkg7
                """
            )
        )
        child8 = Path("mkosi.conf.d/child8.conf")
        child8.write_text(
            dedent(
                f"""\
                [Match]
                ImageId=!{image1} !{image2}

                [Content]
                Packages=testpkg8
                """
            )
        )

        conf = parse([])[1][0]
        assert "testpkg1" in conf.packages
        if image1 == image2:
            assert "testpkg2" in conf.packages
        else:
            assert "testpkg2" not in conf.packages
        assert "testpkg3" in conf.packages
        assert "testpkg4" in conf.packages
        if image1 == image2:
            assert "testpkg5" not in conf.packages
            assert "testpkg6" not in conf.packages
        else:
            assert "testpkg5" not in conf.packages
            assert "testpkg6" in conf.packages
        assert "testpkg7" not in conf.packages
        if image1 == image2:
            assert "testpkg8" not in conf.packages
        else:
            assert "testpkg8" in conf.packages


@pytest.mark.parametrize(
    "op,version", itertools.product(
        ["", "==", "<", ">", "<=", ">="],
        [122, 123, 124],
    )
)
def test_match_imageversion(op: str, version: str) -> None:
    opfunc = {
        "==": operator.eq,
        "!=": operator.ne,
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
    }.get(op, operator.eq,)

    with cd_temp_dir():
        parent = Path("mkosi.conf")
        parent.write_text(
            dedent(
                """\
                [Distribution]
                ImageId=testimage
                ImageVersion=123
                """
            )
        )

        Path("mkosi.conf.d").mkdir()
        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            dedent(
                f"""\
                [Match]
                ImageVersion={op}{version}

                [Content]
                Packages=testpkg1
                """
            )
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            dedent(
                f"""\
                [Match]
                ImageVersion=<200 {op}{version}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            dedent(
                f"""\
                [Match]
                ImageVersion=>9000 {op}{version}

                [Content]
                Packages=testpkg3
                """
            )
        )

        conf = parse([])[1][0]
        assert ("testpkg1" in conf.packages) == opfunc(123, version)
        assert ("testpkg2" in conf.packages) == opfunc(123, version)
        assert "testpkg3" not in conf.packages
