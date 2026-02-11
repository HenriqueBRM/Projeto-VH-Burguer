using VH_Burguer.Domains;

namespace VH_Burguer.Interfaces
{
    public interface iUsuarioRepository
    {
        List<Usuario> Listar();

        //Interrogacao para previnir caso nao venha nenhum usuario na busca
        Usuario? ObterPorId(int id);

        Usuario? ObterPorEmail(string email);

        bool EmailExiste(string email);

        void Adicionar(Usuario usuario);
        void Atualizar(Usuario usuario);
        void Remover(int id);
    }
}
