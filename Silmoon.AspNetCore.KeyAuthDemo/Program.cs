using Silmoon.AspNetCore.Encryption.Extensions;
using Silmoon.AspNetCore.Encryption.Services;
using Silmoon.AspNetCore.Encryption.Services.Interfaces;
using Silmoon.AspNetCore.KeyAuthDemo;
using Silmoon.AspNetCore.KeyAuthDemo.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddControllers().AddNewtonsoftJson();
builder.Services.AddAuthentication().AddCookie();
builder.Services.AddSingleton<Core>();
builder.Services.AddWebAuthn<WebAuthnServiceImpl>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseWebAuthn();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}");
app.MapRazorPages();

app.Run();
