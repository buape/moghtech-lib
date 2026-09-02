use std::{
  path::{Path, PathBuf},
  str::FromStr,
};

/// NOTE. This function will panic if file is non-None and fails to read file contents
pub fn maybe_read_item_from_file<T: FromStrDebugErr>(
  var_file: Option<PathBuf>,
  var: Option<T>,
) -> Option<T> {
  let Some(path) = var_file else { return var };
  let res = std::fs::read_to_string(&path)
    .map_err(|err| Error::<T>::ReadFileError {
      path: path.clone(),
      err,
    })
    .unwrap();
  let res = T::from_str(res.trim())
    .map_err(|err| Error::<T>::ParseValueError {
      path,
      err: err.into(),
    })
    .unwrap();
  Some(res)
}

/// NOTE. This function will panic if file is non-None and fails to read file contents
#[cfg(feature = "tokio")]
pub async fn maybe_read_item_from_file_async<T: FromStrDebugErr>(
  var_file: Option<PathBuf>,
  var: Option<T>,
) -> Option<T> {
  let Some(path) = var_file else { return var };
  let res = tokio::fs::read_to_string(&path)
    .await
    .map_err(|err| Error::<T>::ReadFileError {
      path: path.clone(),
      err,
    })
    .unwrap();
  let res = T::from_str(res.trim())
    .map_err(|err| Error::<T>::ParseValueError {
      path,
      err: err.into(),
    })
    .unwrap();
  Some(res)
}

/// NOTE. This function will panic if file is non-None and fails to read file contents
pub fn maybe_read_list_from_file<T: FromStrDebugErr>(
  var_file: Option<PathBuf>,
  var: Option<Vec<T>>,
) -> Option<Vec<T>> {
  let Some(path) = var_file else { return var };
  Some(parse_list_from_file(&path).unwrap())
}

/// NOTE. This function will panic if file is non-None and fails to read file contents
#[cfg(feature = "tokio")]
pub async fn maybe_read_list_from_file_async<T: FromStrDebugErr>(
  var_file: Option<PathBuf>,
  var: Option<Vec<T>>,
) -> Option<Vec<T>> {
  let Some(path) = var_file else { return var };
  Some(parse_list_from_file_async(&path).await.unwrap())
}

pub trait FromStrDebugErr: FromStr + std::fmt::Debug {
  type Error: std::fmt::Debug + From<Self::Err>;
}

impl FromStrDebugErr for String {
  type Error = <String as FromStr>::Err;
}

impl FromStrDebugErr for i64 {
  type Error = <i64 as FromStr>::Err;
}

#[derive(Debug, thiserror::Error)]
enum Error<T: std::fmt::Debug + FromStrDebugErr> {
  #[error("Failed to read file contents from {path:?} | {err:?}")]
  ReadFileError { path: PathBuf, err: std::io::Error },
  #[error("Failed to parse file contents from {path:?} | {err:?}")]
  ParseValueError { path: PathBuf, err: T::Error },
}

fn parse_list_from_file<T: FromStrDebugErr>(
  path: &Path,
) -> Result<Vec<T>, Error<T>> {
  let contents = std::fs::read_to_string(path).map_err(|err| {
    Error::ReadFileError {
      path: path.to_path_buf(),
      err,
    }
  })?;
  parse_list_from_contents(path, &contents)
}

#[cfg(feature = "tokio")]
async fn parse_list_from_file_async<T: FromStrDebugErr>(
  path: &Path,
) -> Result<Vec<T>, Error<T>> {
  let contents =
    tokio::fs::read_to_string(path).await.map_err(|err| {
      Error::ReadFileError {
        path: path.to_path_buf(),
        err,
      }
    })?;
  parse_list_from_contents(path, &contents)
}

/// Parses comma separated values, skipping empty segments,
/// so empty files and trailing commas / newlines produce
/// no phantom entries.
fn parse_list_from_contents<T: FromStrDebugErr>(
  path: &Path,
  contents: &str,
) -> Result<Vec<T>, Error<T>> {
  contents
    .split(',')
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .map(|s| {
      T::from_str(s).map_err(|err| Error::ParseValueError {
        path: path.to_path_buf(),
        err: err.into(),
      })
    })
    .collect::<Result<Vec<_>, Error<_>>>()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn temp_file(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
      "mogh_secret_file_read_test_{}_{name}",
      std::process::id()
    ));
    std::fs::write(&path, contents).unwrap();
    path
  }

  #[test]
  fn returns_var_when_no_file() {
    assert_eq!(
      maybe_read_item_from_file(None, Some("var".to_string())),
      Some("var".to_string())
    );
    assert_eq!(maybe_read_item_from_file::<String>(None, None), None);
  }

  #[test]
  fn file_takes_precedence_over_var() {
    let path = temp_file("precedence", "from-file\n");
    let res = maybe_read_item_from_file(
      Some(path.clone()),
      Some("from-var".to_string()),
    );
    std::fs::remove_file(path).unwrap();
    assert_eq!(res, Some("from-file".to_string()));
  }

  #[test]
  fn item_contents_are_trimmed_and_parsed() {
    let path = temp_file("i64", "  42\n");
    let res =
      maybe_read_item_from_file::<i64>(Some(path.clone()), None);
    std::fs::remove_file(path).unwrap();
    assert_eq!(res, Some(42));
  }

  #[test]
  #[should_panic]
  fn missing_file_panics() {
    maybe_read_item_from_file::<String>(
      Some(PathBuf::from("/definitely/does/not/exist")),
      None,
    );
  }

  #[test]
  fn list_parses_comma_separated_values() {
    let path = temp_file("list", " 1, 2 ,3\n");
    let res =
      maybe_read_list_from_file::<i64>(Some(path.clone()), None);
    std::fs::remove_file(path).unwrap();
    assert_eq!(res, Some(vec![1, 2, 3]));
  }

  #[test]
  fn list_ignores_empty_segments() {
    let path = temp_file("trailing_comma", "a,b,\n");
    let res =
      maybe_read_list_from_file::<String>(Some(path.clone()), None);
    std::fs::remove_file(path).unwrap();
    assert_eq!(res, Some(vec!["a".to_string(), "b".to_string()]));
  }

  #[test]
  fn empty_list_file_gives_empty_list() {
    let path = temp_file("empty", "\n");
    let res =
      maybe_read_list_from_file::<i64>(Some(path.clone()), None);
    std::fs::remove_file(path).unwrap();
    assert_eq!(res, Some(vec![]));
  }

  #[test]
  fn list_returns_var_when_no_file() {
    assert_eq!(
      maybe_read_list_from_file(None, Some(vec![1i64, 2])),
      Some(vec![1, 2])
    );
    assert_eq!(maybe_read_list_from_file::<i64>(None, None), None);
  }

  #[cfg(feature = "tokio")]
  mod tokio_tests {
    use super::*;

    #[tokio::test]
    async fn async_item_and_list() {
      let path = temp_file("async_item", "  99 \n");
      let res = maybe_read_item_from_file_async::<i64>(
        Some(path.clone()),
        None,
      )
      .await;
      std::fs::remove_file(path).unwrap();
      assert_eq!(res, Some(99));

      let path = temp_file("async_list", "4,5, 6,\n");
      let res = maybe_read_list_from_file_async::<i64>(
        Some(path.clone()),
        None,
      )
      .await;
      std::fs::remove_file(path).unwrap();
      assert_eq!(res, Some(vec![4, 5, 6]));

      assert_eq!(
        maybe_read_item_from_file_async(None, Some(1i64)).await,
        Some(1)
      );
    }
  }
}
