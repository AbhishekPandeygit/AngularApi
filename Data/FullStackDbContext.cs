using FullStack.API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FullStack.API.Data
{
    public class FullStackDbContext : IdentityDbContext<IdentityUser>
    {
        public FullStackDbContext(DbContextOptions options) : base(options) { }
        
        public DbSet<Employee> Employees { get; set; }
        //public DbSet<RegisterModel> RegisterModel { get; set; }
        //public DbSet<LoginModel> LoginModel { get; set; }


    }
}
