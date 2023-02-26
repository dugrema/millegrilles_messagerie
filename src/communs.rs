/// Converti un URL en cle correcte pour dict mongodb
pub fn url_to_mongokey<S>(url: S) -> Result<String, String>
    where S: AsRef<str>
{
    let url = url.as_ref();
    Ok(url.replace(".", "*"))
}