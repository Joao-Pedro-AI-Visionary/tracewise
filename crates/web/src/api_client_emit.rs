//! Minijinja templates embedded in the binary.
//!
//! The SDK text is rendered from the spec model so two runs with the same
//! document produce the same bytes. Templates do not read the clock or the
//! output directory.

use minijinja::Environment;
use serde_json::Value;

use crate::api_client_model::RenderModel;
use crate::error::WebError;

pub(crate) fn render_sdk(
    model: &RenderModel,
    python: bool,
    typescript: bool,
) -> Result<Vec<(String, String)>, WebError> {
    let mut env = Environment::new();
    add(&mut env, "ts_types", include_str!("../templates/api_client/ts_types.ts.j2"))?;
    add(&mut env, "ts_client", include_str!("../templates/api_client/ts_client.ts.j2"))?;
    add(&mut env, "ts_index", include_str!("../templates/api_client/ts_index.ts.j2"))?;
    add(&mut env, "ts_package", include_str!("../templates/api_client/ts_package.json.j2"))?;
    add(&mut env, "ts_tsconfig", include_str!("../templates/api_client/ts_tsconfig.json.j2"))?;
    add(&mut env, "ts_shims", include_str!("../templates/api_client/ts_shims.d.ts.j2"))?;
    add(&mut env, "ts_test", include_str!("../templates/api_client/ts_replay.test.ts.j2"))?;
    add(&mut env, "py_models", include_str!("../templates/api_client/py_models.py.j2"))?;
    add(&mut env, "py_client", include_str!("../templates/api_client/py_client.py.j2"))?;
    add(&mut env, "py_init", include_str!("../templates/api_client/py_init.py.j2"))?;
    add(&mut env, "py_test", include_str!("../templates/api_client/py_replay_test.py.j2"))?;

    let ctx = serde_json::to_value(model)?;
    let mut files = Vec::new();
    if typescript {
        files.push(("typescript/package.json".to_string(), render(&env, "ts_package", &ctx)?));
        files.push(("typescript/tsconfig.json".to_string(), render(&env, "ts_tsconfig", &ctx)?));
        files.push(("typescript/shims.d.ts".to_string(), render(&env, "ts_shims", &ctx)?));
        files.push(("typescript/src/types.ts".to_string(), render(&env, "ts_types", &ctx)?));
        files.push(("typescript/src/client.ts".to_string(), render(&env, "ts_client", &ctx)?));
        files.push(("typescript/src/index.ts".to_string(), render(&env, "ts_index", &ctx)?));
        files.push(("typescript/test/replay.test.ts".to_string(), render(&env, "ts_test", &ctx)?));
    }
    if python {
        let pkg = &model.package_name;
        files.push((format!("python/{pkg}/__init__.py"), render(&env, "py_init", &ctx)?));
        files.push((format!("python/{pkg}/models.py"), render(&env, "py_models", &ctx)?));
        files.push((format!("python/{pkg}/client.py"), render(&env, "py_client", &ctx)?));
        files.push(("python/test_replay.py".to_string(), render(&env, "py_test", &ctx)?));
    }
    Ok(files)
}

fn add(env: &mut Environment<'_>, name: &'static str, source: &'static str) -> Result<(), WebError> {
    env.add_template(name, source).map_err(template_error)
}

fn render(env: &Environment<'_>, name: &str, ctx: &Value) -> Result<String, WebError> {
    let template = env.get_template(name).map_err(template_error)?;
    let mut text = template.render(ctx).map_err(template_error)?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

fn template_error(error: minijinja::Error) -> WebError {
    WebError::Format(format!("API client template failed: {error}"))
}
