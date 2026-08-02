#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Directory,
    RegularFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub kind: NodeKind,
    pub size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VfsError<E> {
    Backend(E),
    InvalidPath,
    NotDirectory,
}

/// Minimal read-only filesystem contract used by kernel services and future userland loaders.
/// Backends own their node representation; callers only retain the associated copyable handle.
pub trait FileSystem {
    type Error;
    type Node: Copy;

    fn root(&self) -> Self::Node;

    fn lookup(
        &mut self,
        parent: Self::Node,
        component: &[u8],
    ) -> Result<Option<Self::Node>, Self::Error>;

    fn metadata(&self, node: Self::Node) -> Result<Metadata, Self::Error>;

    fn read(
        &mut self,
        node: Self::Node,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, Self::Error>;

    /// Resolve an absolute path without allocating path components.
    fn lookup_path(&mut self, path: &[u8]) -> Result<Option<Self::Node>, VfsError<Self::Error>> {
        if path.is_empty() || path[0] != b'/' {
            return Err(VfsError::InvalidPath);
        }

        let mut node = self.root();
        for component in path[1..].split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." {
                continue;
            }
            if component == b".." {
                return Err(VfsError::InvalidPath);
            }
            let metadata = self.metadata(node).map_err(VfsError::Backend)?;
            if metadata.kind != NodeKind::Directory {
                return Err(VfsError::NotDirectory);
            }
            node = match self.lookup(node, component).map_err(VfsError::Backend)? {
                Some(node) => node,
                None => return Ok(None),
            };
        }
        Ok(Some(node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Error {
        InvalidNode,
    }

    struct TinyFileSystem {
        root: bool,
        file: bool,
    }

    impl FileSystem for TinyFileSystem {
        type Error = Error;
        type Node = u8;

        fn root(&self) -> Self::Node {
            0
        }

        fn lookup(
            &mut self,
            parent: Self::Node,
            component: &[u8],
        ) -> Result<Option<Self::Node>, Self::Error> {
            if parent != 0 || component != b"init" {
                return Ok(None);
            }
            Ok(Some(1))
        }

        fn metadata(&self, node: Self::Node) -> Result<Metadata, Self::Error> {
            match node {
                0 if self.root => Ok(Metadata {
                    kind: NodeKind::Directory,
                    size: 0,
                }),
                1 if self.file => Ok(Metadata {
                    kind: NodeKind::RegularFile,
                    size: 4,
                }),
                _ => Err(Error::InvalidNode),
            }
        }

        fn read(
            &mut self,
            node: Self::Node,
            offset: u64,
            buffer: &mut [u8],
        ) -> Result<usize, Self::Error> {
            if node != 1 || offset > 4 {
                return Err(Error::InvalidNode);
            }
            let bytes = b"init";
            let count = core::cmp::min(buffer.len(), bytes.len() - offset as usize);
            buffer[..count].copy_from_slice(&bytes[offset as usize..offset as usize + count]);
            Ok(count)
        }
    }

    #[test]
    fn resolves_absolute_paths_without_allocating() {
        let mut filesystem = TinyFileSystem {
            root: true,
            file: true,
        };
        let node = filesystem.lookup_path(b"//init/.").unwrap().unwrap();
        assert_eq!(
            filesystem.metadata(node).unwrap().kind,
            NodeKind::RegularFile
        );
    }

    #[test]
    fn rejects_relative_and_parent_paths() {
        let mut filesystem = TinyFileSystem {
            root: true,
            file: true,
        };
        assert_eq!(filesystem.lookup_path(b"init"), Err(VfsError::InvalidPath));
        assert_eq!(
            filesystem.lookup_path(b"/../init"),
            Err(VfsError::InvalidPath)
        );
    }
}
